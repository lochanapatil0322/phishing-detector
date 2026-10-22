from mailer import send_email

to = input("Send a test email to: ").strip()
send_email(to, "PhishGuard test", "If you can read this, email sending works.")