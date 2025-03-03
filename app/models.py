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
    cell_number = db.Column(db.String(20))
    # Add passive_deletes=True to prevent cascade deletion
    incidents = db.relationship('Incident', back_populates='reporter', passive_deletes=True)


class IncidentType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    email_to = db.Column(db.String(256))
    # Add passive_deletes=True to prevent cascade deletion
    incidents = db.relationship('Incident', back_populates='incident_type', passive_deletes=True)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(db.Integer, db.ForeignKey('incident_type.id', ondelete='SET NULL'), nullable=True)
    # Add these fields to store original values
    type_name = db.Column(db.String(64))  # Store incident type name
    reporter_name = db.Column(db.String(64))  # Store personnel name
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    personnel_id = db.Column(db.Integer, db.ForeignKey('personnel.id', ondelete='SET NULL'), nullable=True)
    
    # New fields for resolution
    resolution = db.Column(db.String(500), nullable=True)
    resolved_by = db.Column(db.String(64), nullable=True)
    resolved_timestamp = db.Column(db.DateTime, nullable=True)
    resolved_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    incident_type = db.relationship('IncidentType', back_populates='incidents')
    reporter = db.relationship('Personnel', back_populates='incidents')

    ip_address = db.Column(db.String(45))

class EmailSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(128))
    smtp_port = db.Column(db.Integer)
    smtp_username = db.Column(db.String(128))
    smtp_password = db.Column(db.String(128))
    from_address = db.Column(db.String(128))

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 characters

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(64))
    details = db.Column(db.String(500))

class ResolutionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'))
    resolution_text = db.Column(db.String(500))
    resolved_by = db.Column(db.String(64))
    resolved_timestamp = db.Column(db.DateTime)
    resolved_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # For when resolution is removed
    unresolve_timestamp = db.Column(db.DateTime, nullable=True)
    unresolved_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationship to the incident
    incident = db.relationship('Incident', backref=db.backref('resolution_history', lazy=True))