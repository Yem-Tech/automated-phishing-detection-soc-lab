import os
import imaplib
import email
from email.header import decode_header
import time
import requests
import socket
import json
import re
import base64
from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
VT_API_KEY = os.getenv("VT_API_KEY")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
SPLUNK_URL = os.getenv("SPLUNK_URL")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "gmail_logs")


IMAP_SERVER = "imap.gmail.com"

FOLDERS = [
    "INBOX",
    "[Gmail]/Spam"
]

# Check Gmail every 4 minutes
CHECK_INTERVAL = 4 * 60

seen_uids = set()


def validate_environment():
    required_vars = {
        "EMAIL_USER": EMAIL_USER,
        "EMAIL_PASS": EMAIL_PASS,
        "VT_API_KEY": VT_API_KEY,
        "SPLUNK_TOKEN": SPLUNK_TOKEN,
        "SPLUNK_URL": SPLUNK_URL,
    }

    missing = [
        name
        for name, value in required_vars.items()
        if not value
    ]

    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing)
        )


def decode_mime(value):
    if not value:
        return ""

    decoded_parts = decode_header(value)

    return "".join(
        str(part[0], part[1] or "utf-8")
        if isinstance(part[0], bytes)
        else str(part[0])
        for part in decoded_parts
    )


def extract_links(text):
    return re.findall(
        r"https?://\S+",
        text or ""
    )


def vt_scan_url(url):
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }

        # Submit URL to VirusTotal
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            return {
                "error": f"submit failed: {response.status_code}",
                "details": response.text
            }

        analysis_id = response.json()["data"]["id"]

        # Allow VirusTotal time to process the URL
        time.sleep(15)

        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=30
        )

        if analysis_response.status_code != 200:
            return {
                "error":
                    f"analysis fetch failed: "
                    f"{analysis_response.status_code}",
                "details": analysis_response.text
            }

        result = analysis_response.json()

        stats = (
            result
            .get("data", {})
            .get("attributes", {})
            .get("stats", {})
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "analysis_id": analysis_id
        }

    except Exception as exc:
        return {
            "error": str(exc)
        }


def send_to_splunk(event):
    payload = {
        "time": int(time.time()),
        "host": socket.gethostname(),
        "source": "email_monitor",
        "sourcetype": "email_event",
        "index": SPLUNK_INDEX,
        "event": event
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            SPLUNK_URL,
            headers=headers,
            data=json.dumps(payload),
            timeout=30,

            # Lab only:
            # The Splunk lab server uses a self-signed certificate.
            # Production deployments should validate certificates.
            verify=False
        )

        if response.status_code == 200:
            print("[+] Event sent to Splunk")
        else:
            print(
                f"[-] Splunk HEC error: "
                f"{response.status_code} - {response.text}"
            )

    except Exception as exc:
        print(
            "[-] Failed to send event to Splunk:",
            exc
        )


def process_email(msg):
    email_data = {
        "from": decode_mime(msg.get("From")),
        "to": decode_mime(msg.get("To")),
        "subject": decode_mime(msg.get("Subject")),
        "date": msg.get("Date"),
        "attachments": [],
        "links": [],
        "vt_results": [],
        "body": ""
    }

    for part in msg.walk():
        content_type = part.get_content_type()

        content_disposition = str(
            part.get("Content-Disposition")
        )

        # Extract plain-text email body
        if (
            content_type == "text/plain"
            and "attachment" not in content_disposition
        ):
            charset = (
                part.get_content_charset()
                or "utf-8"
            )

            try:
                payload = part.get_payload(
                    decode=True
                )

                if payload:
                    email_data["body"] = payload.decode(
                        charset,
                        errors="ignore"
                    )

            except Exception:
                continue

        # Extract attachment metadata and contents
        if part.get_filename():
            filename = decode_mime(
                part.get_filename()
            )

            attachment_payload = (
                part.get_payload(
                    decode=True
                )
            )

            if filename and attachment_payload:
                encoded_content = (
                    base64
                    .b64encode(
                        attachment_payload
                    )
                    .decode("utf-8")
                )

                email_data[
                    "attachments"
                ].append(
                    {
                        "filename": filename,
                        "content_base64":
                            encoded_content,
                        "content_type":
                            content_type
                    }
                )

    links = extract_links(
        email_data["body"]
    )

    email_data["links"] = links

    for link in links:
        print(
            f"[*] Scanning link: {link}"
        )

        vt_result = vt_scan_url(
            link
        )

        email_data[
            "vt_results"
        ].append(
            {
                "url": link,
                "result": vt_result
            }
        )

    return email_data


def main():
    validate_environment()

    while True:
        try:
            mail = imaplib.IMAP4_SSL(
                IMAP_SERVER
            )

            mail.login(
                EMAIL_USER,
                EMAIL_PASS
            )

            for folder in FOLDERS:
                print(
                    f"[*] Checking folder: "
                    f"{folder}"
                )

                status, _ = mail.select(
                    folder
                )

                if status != "OK":
                    print(
                        f"[-] Unable to open "
                        f"{folder}"
                    )
                    continue

                status, messages = (
                    mail.search(
                        None,
                        "UNSEEN"
                    )
                )

                if status != "OK":
                    print(
                        "[-] Error fetching messages."
                    )
                    continue

                for num in messages[0].split():
                    typ, msg_data = mail.fetch(
                        num,
                        "(RFC822 UID)"
                    )

                    if typ != "OK":
                        continue

                    raw_email = msg_data[0][1]

                    uid_line = (
                        msg_data[0][0]
                        .decode()
                    )

                    match = re.search(
                        r"UID (\d+)",
                        uid_line
                    )

                    uid = (
                        match.group(1)
                        if match
                        else num.decode()
                    )

                    if uid in seen_uids:
                        continue

                    seen_uids.add(uid)

                    msg = email.message_from_bytes(
                        raw_email
                    )

                    print(
                        "[*] Email:",
                        decode_mime(
                            msg.get("Subject")
                        )
                    )

                    event = process_email(
                        msg
                    )

                    send_to_splunk(
                        event
                    )

            mail.logout()

        except Exception as exc:
            print(
                "[-] Main loop error:",
                exc
            )

        print(
            f"[*] Sleeping for "
            f"{CHECK_INTERVAL // 60} "
            f"minutes...\n"
        )

        time.sleep(
            CHECK_INTERVAL
        )


if __name__ == "__main__":
    main()
