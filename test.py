# test.py
from app import app, db
from app.models import EmailSettings
from sqlalchemy import text

with app.app_context():
    # Get current settings
    settings = EmailSettings.query.first()
    
    # Check if timezone attribute exists
    if hasattr(settings, 'timezone'):
        print(f"Timezone attribute exists, current value: {settings.timezone}")
    else:
        print("Timezone attribute does not exist on the model")
        
    # Check the actual database value
    try:
        result = db.session.execute(text('SELECT timezone FROM email_settings WHERE id = 1')).fetchone()
        if result:
            print(f"Database timezone value: {result[0]}")
        else:
            print("No timezone value found in database")
    except Exception as e:
        print(f"Error querying database: {str(e)}")