from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Add the timezone column to the database table
        db.session.execute(text('ALTER TABLE email_settings ADD COLUMN timezone VARCHAR(64) DEFAULT "UTC"'))
        db.session.commit()
        print("Added timezone column successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding timezone column: {str(e)}")