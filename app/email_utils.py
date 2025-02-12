import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
from app.models import EmailSettings

def send_incident_email(incident):
    # Get email addresses (comma separated)
    if not incident.incident_type.email_to:
        return
    
    email_addresses = [email.strip() for email in incident.incident_type.email_to.split(',')]
    
    # Get email settings
    settings = EmailSettings.query.first()
    if not settings:
        print("Email settings not configured")
        return
    
    # Create message
    msg = MIMEMultipart()
    msg['Subject'] = f"New {incident.incident_type.name} Incident Report"
    msg['From'] = settings.from_address
    
    # Create email body
    body = f"""
    New Incident Report
    
    Date/Time: {incident.timestamp.strftime('%Y-%m-%d %H:%M')}
    Type: {incident.incident_type.name}
    Reported By: {incident.reporter.name}
    
    Description:
    {incident.description}
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email
    try:
        server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
        server.ehlo()  # Can be omitted
        server.starttls()  # Enable TLS
        server.ehlo()  # Can be omitted
        server.login(settings.smtp_username, settings.smtp_password)
        
        for email in email_addresses:
            msg['To'] = email
            text = msg.as_string()
            server.sendmail(settings.from_address, email, text)
            
        server.quit()
        print("Email sent successfully")
                
    except Exception as e:
        print(f"Failed to send email: {str(e)}")  # You might want to log this
        raise  # This will help you see the actual error in your Flask app