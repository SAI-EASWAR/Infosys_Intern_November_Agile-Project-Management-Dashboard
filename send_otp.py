import random
import smtplib
from email.mime.text import MIMEText

def send_email_with_otp(sender_email, sender_password, receiver_email):
    try:
        otp = str(random.randint(100000, 999999))
        # Email subject and body
        subject = "Your OTP Code"
        body = f"Your OTP is: {otp}"
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
        return otp  # Return the generated OTP
    except Exception as e:
        raise Exception(f"Failed to send email: {e}")
