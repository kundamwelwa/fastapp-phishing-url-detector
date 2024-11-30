import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi import HTTPException
from typing import Optional

def send_email_with_report(
    to_email: str, 
    report_content: str, 
    subject: Optional[str] = "Phishing Detection Report"
):
    """
    Sends an email with the provided report content.

    Args:
        to_email (str): The recipient's email address.
        report_content (str): The content of the report to be sent.
        subject (str): The email subject. Default is "Phishing Detection Report".

    Raises:
        HTTPException: If there is an error in sending the email.
    """
    try:
        # Fetch credentials from environment variables
        sender_email = os.getenv("EMAIL_USER")
        sender_password = os.getenv("EMAIL_PASSWORD")

        # Ensure credentials are loaded
        if not sender_email or not sender_password:
            raise HTTPException(
                status_code=500,
                detail="Email credentials not found. Ensure environment variables are set."
            )

        # Set up the email server configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Compose the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the email body
        body = MIMEText(report_content, 'plain')
        msg.attach(body)

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())

    except smtplib.SMTPAuthenticationError:
        raise HTTPException(
            status_code=500,
            detail="Authentication error: Unable to send email. Please verify your credentials."
        )
    except smtplib.SMTPException as e:
        raise HTTPException(
            status_code=500,
            detail=f"SMTP error occurred: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )
