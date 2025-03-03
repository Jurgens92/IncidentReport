from app import app, db
from sqlalchemy import text, exc

with app.app_context():
    # Safely add IP address column
    try:
        db.session.execute(text('ALTER TABLE incident ADD COLUMN ip_address VARCHAR(45)'))
        print("Added ip_address column successfully!")
    except exc.OperationalError as e:
        if "duplicate column name" in str(e):
            print("ip_address column already exists, skipping...")
        else:
            print(f"Error when adding ip_address column: {str(e)}")
    
    # Commit any successful changes
    db.session.commit()
    
    print("Database update completed!")