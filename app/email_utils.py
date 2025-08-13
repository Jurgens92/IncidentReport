import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.models import EmailSettings
import pytz


def _get_timezone():
    """Return a pytz timezone from settings, defaulting to UTC on error."""
    settings = EmailSettings.query.first()
    tz_name = (settings.timezone if settings and settings.timezone else 'UTC')
    try:
        return pytz.timezone(tz_name), tz_name
    except Exception:
        # Fallback to UTC if the stored timezone is invalid
        return pytz.utc, 'UTC'


def _format_dt_local(dt, fmt='%Y-%m-%d %H:%M'):
    """Format a datetime in the configured timezone, assuming incoming dt is UTC or naive UTC."""
    if dt is None:
        return ""
    tz, _ = _get_timezone()
    # Treat naive datetimes as UTC (as the app stores with datetime.utcnow)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(tz).strftime(fmt)

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
    _, tz_name = _get_timezone()
    body = f"""
New Incident Report

Date/Time ({tz_name}): {_format_dt_local(incident.timestamp)}
Type: {incident.incident_type.name}
Reported By: {getattr(incident.reporter, 'name', None) or incident.reporter_name}
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
    _, tz_name = _get_timezone()
    body = f"""
Incident Resolved

Original Incident:
Date/Time ({tz_name}): {_format_dt_local(incident.timestamp)}
Type: {incident.incident_type.name}
Reported By: {incident.reporter_name}
Description: {incident.description}

Resolution:
Date/Time ({tz_name}): {_format_dt_local(incident.resolved_timestamp)}
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