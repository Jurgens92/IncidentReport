import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.models import EmailSettings

def send_incident_email(incident):
    """Send email notification for an incident."""
    # Skip if no email addresses configured
    if not incident.incident_type.email_to:
        return
    
    # Get email settings
    settings = EmailSettings.query.first()
    if not settings or not settings.smtp_server:
        print("Email settings not configured")
        return

    # Parse recipient email addresses
    recipients = [addr.strip() for addr in incident.incident_type.email_to.split(',') if addr.strip()]
    if not recipients:
        return

    # Create message
    msg = MIMEMultipart()
    msg['From'] = settings.from_address
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = f"New {incident.incident_type.name} Incident Report"

    # Create message body
    body = f"""
New Incident Report

Date/Time: {incident.timestamp.strftime('%Y-%m-%d %H:%M')}
Type: {incident.incident_type.name}
Reported By: {incident.reporter.name}
Reported From IP: {incident.ip_address or 'Unknown'}

Description:
{incident.description}
"""
    msg.attach(MIMEText(body, 'plain'))

    # Connect to SMTP server and send email
    try:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as server:
            server.starttls()
            
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            
            server.send_message(msg)
            print(f"Email sent successfully to {', '.join(recipients)}")
            
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        # Don't raise the exception, just log it

def send_resolution_email(incident):
    """Send email notification for a resolved incident."""
    if incident.incident_type is None or not incident.incident_type.email_to:
        print(f"No email notification for incident {incident.id}: Missing incident type or email")
        return
    # Skip if no email addresses configured
    if not incident.incident_type.email_to:
        return
    
    # Get email settings
    settings = EmailSettings.query.first()
    if not settings or not settings.smtp_server:
        print("Email settings not configured")
        return

    # Parse recipient email addresses
    recipients = [addr.strip() for addr in incident.incident_type.email_to.split(',') if addr.strip()]
    if not recipients:
        return

    # Create message
    msg = MIMEMultipart()
    msg['From'] = settings.from_address
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = f"RESOLVED: {incident.incident_type.name} Incident"

    # Create message body
    body = f"""
Incident Resolved

Original Incident:
Date/Time: {incident.timestamp.strftime('%Y-%m-%d %H:%M')}
Type: {incident.incident_type.name}
Reported By: {incident.reporter_name}
Description: {incident.description}

Resolution:
Date/Time: {incident.resolved_timestamp.strftime('%Y-%m-%d %H:%M')}
Resolved By: {incident.resolved_by}
Resolution Details: {incident.resolution}
"""
    msg.attach(MIMEText(body, 'plain'))

    # Connect to SMTP server and send email
    try:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as server:
            server.starttls()
            
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            
            server.send_message(msg)
            print(f"Resolution email sent successfully to {', '.join(recipients)}")
            
    except Exception as e:
        print(f"Failed to send resolution email: {str(e)}")
        # Don't raise the exception, just log it