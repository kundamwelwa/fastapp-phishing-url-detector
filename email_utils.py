import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from fastapi import HTTPException
import matplotlib.pyplot as plt
import io


def generate_pie_chart(phishing_count: int, legitimate_count: int):
    """
    Generates a pie chart of phishing vs legitimate URLs with dynamic colors.

    Args:
        phishing_count (int): Number of phishing URLs.
        legitimate_count (int): Number of legitimate URLs.

    Returns:
        BytesIO: The image data of the pie chart.
    """
    labels = ['Phishing URLs', 'Legitimate URLs']
    sizes = [phishing_count, legitimate_count]

    # Dynamically assign colors based on counts
    colors = ['#FF6666' if phishing_count >= legitimate_count else '#FF9999',
              '#66CC66' if legitimate_count > phishing_count else '#99CC99']
    
    explode = (0.1, 0)  # Slightly explode the phishing slice for emphasis.

    fig, ax = plt.subplots()
    ax.pie(
        sizes, explode=explode, labels=labels, colors=colors,
        autopct='%1.1f%%', shadow=True, startangle=140
    )
    ax.axis('equal')  # Equal aspect ratio ensures the pie chart is circular.

    # Save the chart to a BytesIO object
    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)
    plt.close(fig)
    return image_stream


def send_email_with_report(to_email: str, report_content: str, phishing_count: int, legitimate_count: int,
                           phishing_urls: list, legitimate_urls: list, subject="Phishing Detection Report"):
    """
    Sends an email containing a phishing detection report with a pie chart and tables of URLs.

    Args:
        to_email (str): Recipient email address.
        report_content (str): Plain-text report content.
        phishing_urls (list): List of phishing URLs.
        legitimate_urls (list): List of legitimate URLs.
        phishing_count (int): Number of detected phishing URLs.
        legitimate_count (int): Number of legitimate URLs detected.
        subject (str): Email subject. Default is "Phishing Detection Report".

    Raises:
        HTTPException: For any SMTP or authentication issues.
    """
    try:
        # Load credentials from environment variables
        sender_email = os.getenv("EMAIL_USER")
        sender_password = os.getenv("EMAIL_PASSWORD")

        # Check if credentials are available
        if not sender_email or not sender_password:
            raise HTTPException(
                status_code=500,
                detail="Email credentials not found. Ensure environment variables are set."
            )

        # SMTP server configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Generate the pie chart image
        image_stream = generate_pie_chart(phishing_count, legitimate_count)

        # Generate HTML table content for phishing and legitimate URLs
        phishing_table = "".join([f"<tr style='background-color:#FF6666;'><td>{url}</td></tr>" for url in phishing_urls])
        legitimate_table = "".join([f"<tr style='background-color:#66CC66;'><td>{url}</td></tr>" for url in legitimate_urls])

        # Compose the email in HTML
        html_content = f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        padding: 20px;
                    }}
                    .header {{
                        text-align: center;
                        padding: 15px;
                        background-color: #4CAF50;
                        color: white;
                        border-radius: 8px;
                    }}
                    .content {{
                        background-color: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0px 2px 5px rgba(0, 0, 0, 0.1);
                    }}
                    .statistics {{
                        font-size: 16px;
                        margin-bottom: 20px;
                    }}
                    .highlight {{
                        font-weight: bold;
                        color: #4CAF50;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }}
                    th, td {{
                        padding: 10px;
                        border: 1px solid #ddd;
                        text-align: left;
                    }}
                    th {{
                        background-color: #4CAF50;
                        color: white;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>Phishing Detection Report</h2>
                </div>

                <div class="content">
                    <p class="statistics">
                        Total URLs: <span class="highlight">{phishing_count + legitimate_count}</span><br>
                        Phishing URLs: <span class="highlight">{phishing_count}</span><br>
                        Legitimate URLs: <span class="highlight">{legitimate_count}</span><br>
                        Phishing Percentage: <span class="highlight">{(phishing_count / (phishing_count + legitimate_count)) * 100:.2f}%</span><br>
                        Legitimate Percentage: <span class="highlight">{(legitimate_count / (phishing_count + legitimate_count)) * 100:.2f}%</span>
                    </p>

                    <img src="cid:pie_chart" alt="Pie Chart" style="display:block; margin: 20px auto; max-width: 400px;">

                    <h3>Phishing URLs</h3>
                    <table>
                        <tr><th>URL</th></tr>
                        {phishing_table}
                    </table>

                    <h3>Legitimate URLs</h3>
                    <table>
                        <tr><th>URL</th></tr>
                        {legitimate_table}
                    </table>
                </div>
            </body>
        </html>
        """

        # Compose the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the plain text content
        msg.attach(MIMEText(report_content, 'plain'))

        # Attach the HTML content
        msg.attach(MIMEText(html_content, 'html'))

        # Attach the pie chart image
        image = MIMEImage(image_stream.read(), name="pie_chart.png")
        image.add_header('Content-ID', '<pie_chart>')  # Reference in the HTML content
        msg.attach(image)

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)  # Authenticate
            server.sendmail(sender_email, to_email, msg.as_string())  # Send the email

    except Exception as e:
        print("Unexpected error during email sending:", e)
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
