import os
import smtplib
import ssl
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()


def send_email(to: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("MAIL_FROM") or user

    # Development mode: no email account configured, so show the message here
    if not user or not password:
        print("\n" + "=" * 60)
        print("[DEV MODE: email not configured] Message that would be sent:")
        print("To:     ", to)
        print("Subject:", subject)
        print(body)
        print("=" * 60 + "\n")
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(user, password)
            server.send_message(msg)
        print(f"[mail] Sent to {to}")
    except smtplib.SMTPAuthenticationError:
        print("[mail] FAILED: Gmail rejected the login. Check SMTP_USER, and make sure "
              "SMTP_PASSWORD is the 16-character App Password (not your normal password).")
    except (smtplib.SMTPException, OSError) as exc:
        print("[mail] FAILED:", type(exc).__name__, exc)