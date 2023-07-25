import email
import pathlib
import re
from typing import List, Any, Dict, Optional

import requests

EML_FILE_NAME = 'order.eml'
# I put it here intentionally for simplicity
VIRUS_TOTAL_API_KEY = '570030d3dc68c2a71562eefaef360410d0e2fb0dc336ec68ece7c05d85514659'


def get_eml_file_path(filename: str) -> pathlib.Path:
    script_dir = pathlib.Path.cwd()
    eml_file_path = script_dir / filename
    return eml_file_path


def parse_eml_headers(eml_file_path: pathlib.Path) -> Dict[str, Any]:
    with open(eml_file_path, 'r', encoding='utf-8') as eml_file:
        msg = email.message_from_file(eml_file)
        return dict(msg.items())


def parse_eml_body(eml_file_path: pathlib.Path) -> Optional[str]:
    with open(eml_file_path, 'r', encoding='utf-8') as eml_file:
        msg = email.message_from_file(eml_file)
        for message in msg.walk():
            if message.get_content_type() == "text/plain":
                return message.get_payload()
        return None


def find_unique_emails_in_string(email_string: str) -> List[str]:
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    match: List[str] = re.findall(email_pattern, email_string)
    return list(set(match)) if match else []


def all_unique_url_addresses_found_in_email(string: str) -> List[str]:
    url_pattern = r'https?://\S+|www\.\S+'
    urls_found = re.findall(url_pattern, string)
    return list(set(urls_found)) if urls_found else []


def extract_domain_from_email_string(email_string: str) -> Optional[str]:
    founded_email: List[str] = find_unique_emails_in_string(email_string)
    if not founded_email:
        return None

    match = re.search(r'@(.+)$', founded_email[0])
    if match:
        return match.group(1)
    return None


def does_the_message_id_align_with_the_sender(msg: Dict[str, Any]) -> bool:
    sender_domain: str = extract_domain_from_email_string(msg.get('From'))
    message_id_domain: str = extract_domain_from_email_string(msg.get('Message-Id'))
    if sender_domain and message_id_domain:
        return sender_domain == message_id_domain
    return False


def there_is_valid_DMARC(msg: Dict[str, Any]) -> Optional[str]:
    dmarc = msg.get('Authentication-Results')
    return dmarc


def the_recipient_is(msg: Dict[str, Any]):
    return msg.get('To')


def url_is_loading_a_content(url: str) -> bool:
    try:
        # disregard post/put/delete methods by now
        response = requests.get(url)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException:
        return False


def check_url_in_virus_total(url: str) -> dict:

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    check_id_response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    check_id_link = check_id_response.json()['data']['links']['self']
    if not check_id_link:
        print('No check id link found')

    report = requests.get(check_id_link, headers=headers)
    return report.json()['data']['attributes']


def main() -> None:
    eml_file_path: pathlib.Path = get_eml_file_path(EML_FILE_NAME)

    headers: Dict[str, Any] = parse_eml_headers(eml_file_path)

    print('The message ID aligns with the sender: ', does_the_message_id_align_with_the_sender(headers))
    print('There is valid DMARC: ', there_is_valid_DMARC(headers))
    print('The recipient is: ', the_recipient_is(headers))

    body: Optional[str] = parse_eml_body(eml_file_path)
    if not body:
        print('There is no body in the email')
        return

    print('All email addresses found in email body: ', find_unique_emails_in_string(body))

    all_url_addresses_in_email = all_unique_url_addresses_found_in_email(body)

    print('All url addresses found in email: ', all_url_addresses_in_email)

    for url in all_url_addresses_in_email:
        print(f'URL {url} is loading a content: {url_is_loading_a_content(url)}')

    for url in all_url_addresses_in_email:
        print(f'Virus total for email: {url} response: {check_url_in_virus_total(url)}')


if __name__ == '__main__':
    main()
