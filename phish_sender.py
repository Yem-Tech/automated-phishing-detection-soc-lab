import os
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load credentials from .env
load_dotenv()

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

SENDER_EMAIL = os.getenv("EMAIL_USER")
SENDER_PASSWORD = os.getenv("EMAIL_PASS")

# Send the simulation back to the same lab mailbox
TARGET_EMAILS = [os.getenv("EMAIL_USER")]

SUBJECT = "URGENT: Security Update Required for BNS Account"

BODY_TEMPLATE = """
Dear User,

We detected suspicious login attempts on your BNS account.
Please verify your identity immediately to avoid account suspension.

Click here to secure your account:
http://bnscyberlab.com

Best regards,
BNS Cyber Security Team

THIS IS A SECURITY LAB SIMULATION.
"""


def send_simulation_emails():
    print("[+] Starting Phishing Simulation Loop...")

    for i in range(1, 11):
        try:
            msg = MIMEMultipart()
            msg["From"] = SENDER_EMAIL
            msg["To"] = TARGET_EMAILS[0]
            msg["Subject"] = f"{SUBJECT} (Simulation #{i})"

            msg.attach(MIMEText(BODY_TEMPLATE, "plain"))

            server = smtplib.SMTP_SSL(
                SMTP_SERVER,
                SMTP_PORT,
                timeout=30
            )

            server.login(
                SENDER_EMAIL,
                SENDER_PASSWORD
            )

            server.sendmail(
                SENDER_EMAIL,
                TARGET_EMAILS,
                msg.as_string()
            )

            server.quit()

            print(
                f"[+] Sent email {i}: "
                "Simulated phishing message delivered."
            )

            print(
                "[*] Waiting 60 seconds before sending the next one..."
            )

            time.sleep(60)

        except Exception as e:
            print(f"[-] Error sending email {i}: {e}")
            break


if __name__ == "__main__":
    send_simulation_emails()
