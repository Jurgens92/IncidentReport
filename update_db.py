from app import app, db
from sqlalchemy import text

with app.app_context():
    # Add the columns we need using SQLAlchemy text() for raw SQL
    db.session.execute(text('ALTER TABLE incident ADD COLUMN resolution TEXT'))
    db.session.execute(text('ALTER TABLE incident ADD COLUMN resolved_by VARCHAR(64)'))
    db.session.execute(text('ALTER TABLE incident ADD COLUMN resolved_timestamp DATETIME'))
    db.session.execute(text('ALTER TABLE incident ADD COLUMN resolved_by_user_id INTEGER REFERENCES user(id)'))
    db.session.commit()
    
    print("Database updated successfully!")