from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Personnel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    # Remove the backref here since we'll define it in the Incident model
    incidents = db.relationship('Incident', back_populates='reporter')

class IncidentType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    email_to = db.Column(db.String(256))
    incidents = db.relationship('Incident', back_populates='incident_type')

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(db.Integer, db.ForeignKey('incident_type.id'))
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    personnel_id = db.Column(db.Integer, db.ForeignKey('personnel.id'))
    
    # Define relationships with back_populates instead of backref
    incident_type = db.relationship('IncidentType', back_populates='incidents')
    reporter = db.relationship('Personnel', back_populates='incidents')

class EmailSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(128))
    smtp_port = db.Column(db.Integer)
    smtp_username = db.Column(db.String(128))
    smtp_password = db.Column(db.String(128))
    from_address = db.Column(db.String(128))