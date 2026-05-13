import re
import httpx
from typing import Optional, List
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from plain text using regex."""
    if not text:
        return []

    # Regex for http(s) URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates


def strip_html_tags(html: str) -> str:
    """Strip HTML tags to get plain text."""
    if not html:
        return ""

    # Remove script and style tags with their content
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)

    # Replace common HTML entities
    html = html.replace('&nbsp;', ' ')
    html = html.replace('&lt;', '<')
    html = html.replace('&gt;', '>')
    html = html.replace('&amp;', '&')
    html = html.replace('&quot;', '"')

    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', ' ', html)

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def extract_urls_from_html(html: str) -> List[str]:
    """Extract URLs from HTML body."""
    if not html:
        return []

    # Find all href attributes
    href_pattern = r'href=["\']([^"\']+)["\']'
    urls = re.findall(href_pattern, html, re.IGNORECASE)

    # Filter to only http(s) URLs
    urls = [url for url in urls if url.startswith('http://') or url.startswith('https://')]

    return list(set(urls))  # Remove duplicates


def get_gmail_service(access_token: str):
    """Create Gmail API service with the given access token."""
    credentials = Credentials(access_token)
    return build('gmail', 'v1', credentials=credentials)


async def get_emails_list(access_token: str, max_results: int = 20) -> List[dict]:
    """
    Get list of emails from Gmail inbox.
    Returns: [{id, threadId, subject, from, snippet, date}]
    """
    try:
        service = get_gmail_service(access_token)

        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=max_results
        ).execute()

        messages = results.get('messages', [])

        emails = []
        for msg in messages:
            # Get full message details
            message = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='full'
            ).execute()

            headers = message.get('payload', {}).get('headers', [])
            header_dict = {h['name'].lower(): h['value'] for h in headers}

            subject = header_dict.get('subject', '(sin asunto)')
            email_from = header_dict.get('from', 'unknown')
            date = header_dict.get('date', '')

            snippet = message.get('snippet', '')

            emails.append({
                'id': msg['id'],
                'threadId': msg.get('threadId', ''),
                'subject': subject,
                'from': email_from,
                'snippet': snippet,
                'date': date
            })

        return emails

    except Exception as e:
        raise Exception(f"Failed to get emails list: {str(e)}")


async def get_email_detail(access_token: str, email_id: str) -> dict:
    """
    Get detailed information of a specific email.
    Returns: {id, subject, from, to, date, body_text, body_html, urls: [list of urls]}
    """
    try:
        service = get_gmail_service(access_token)

        message = service.users().messages().get(
            userId='me',
            id=email_id,
            format='full'
        ).execute()

        # Parse headers
        headers = message.get('payload', {}).get('headers', [])
        header_dict = {h['name'].lower(): h['value'] for h in headers}

        subject = header_dict.get('subject', '(sin asunto)')
        email_from = header_dict.get('from', 'unknown')
        email_to = header_dict.get('to', '')
        date = header_dict.get('date', '')

        # Get body
        body_plain = None
        body_html = None
        urls = []

        payload = message.get('payload', {})

        # Check for multipart messages
        if 'parts' in payload:
            for part in payload['parts']:
                mime_type = part.get('mimeType', '')

                if mime_type == 'text/plain' and 'data' in part.get('body', {}):
                    import base64
                    body_data = part['body']['data']
                    body_plain = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                    urls.extend(extract_urls_from_text(body_plain))

                elif mime_type == 'text/html' and 'data' in part.get('body', {}):
                    import base64
                    body_data = part['body']['data']
                    body_html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                    urls.extend(extract_urls_from_html(body_html))

                # Handle nested parts
                if 'parts' in part:
                    for nested_part in part['parts']:
                        nested_mime = nested_part.get('mimeType', '')

                        if nested_mime == 'text/plain' and 'data' in nested_part.get('body', {}):
                            import base64
                            body_data = nested_part['body']['data']
                            body_plain = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                            urls.extend(extract_urls_from_text(body_plain))

                        elif nested_mime == 'text/html' and 'data' in nested_part.get('body', {}):
                            import base64
                            body_data = nested_part['body']['data']
                            body_html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                            urls.extend(extract_urls_from_html(body_html))
        else:
            # Simple message
            if 'data' in payload.get('body', {}):
                import base64
                body_data = payload['body']['data']
                mime_type = payload.get('mimeType', 'text/plain')

                if mime_type == 'text/html':
                    body_html = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                    urls.extend(extract_urls_from_html(body_html))
                else:
                    body_plain = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                    urls.extend(extract_urls_from_text(body_plain))

        # If we have HTML but no plain text, strip HTML to get plain
        if body_html and not body_plain:
            body_plain = strip_html_tags(body_html)
            urls.extend(extract_urls_from_text(body_plain))

        # If we have plain but no HTML, skip
        # Deduplicate URLs
        urls = list(set(urls))

        # Get attachments
        attachments = []
        if 'parts' in payload:
            for part in payload['parts']:
                filename = part.get('filename', '')
                if filename:
                    attachments.append({
                        'filename': filename,
                        'mimeType': part.get('mimeType', 'application/octet-stream'),
                        'sizeBytes': part.get('body', {}).get('size', 0)
                    })

        # Get labels
        labels = message.get('labelIds', [])

        return {
            'id': message['id'],
            'thread_id': message.get('threadId', ''),
            'subject': subject,
            'from': email_from,
            'from_name': None,  # Will be parsed in route
            'from_email': None,  # Will be parsed in route
            'to': email_to,
            'date': date,
            'body_plain': body_plain[:10000] if body_plain else None,  # Truncate to 10K
            'body_html': body_html[:10000] if body_html else None,  # Truncate to 10K
            'urls': urls,
            'attachments': attachments,
            'labels': labels
        }

    except Exception as e:
        raise Exception(f"Failed to get email detail: {str(e)}")