# send_email.py
import smtplib
from email.mime.text import MIMEText

def send_email(sender_email, sender_password, receiver_email, subject, body):
    """Send an email using SMTP."""
    try:
        # Connect to the Gmail SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)  # Log in to the email account

            # Create the email
            message = MIMEText(body, "plain")
            message["Subject"] = subject
            message["From"] = sender_email
            message["To"] = receiver_email

            # Send the email
            server.send_message(message)
    except Exception as e:
        raise Exception(f"Failed to send email: {e}")
