from app import app, db
from app.models import User, Personnel, IncidentType
from app.models import EmailSettings

# Create an application context
with app.app_context():
    # Drop and recreate all tables
    db.drop_all()
    db.create_all()

    # Create admin user
    admin = User(username='admin', is_admin=True)
    admin.set_password('admin')
    db.session.add(admin)
    db.session.commit()

    default_email_settings = EmailSettings(
    smtp_server='smtp.example.com',
    smtp_port=587,
    smtp_username='',
    smtp_password='',
    from_address='noreply@example.com'
    )
    db.session.add(default_email_settings)
    db.session.commit()

    # Add initial incident types with email fields
    initial_types = [
        {'name': 'Street Light', 'email_to': ''},
        {'name': 'Boom Gate', 'email_to': ''},
        {'name': 'Fence', 'email_to': ''},
        {'name': 'Other', 'email_to': ''}
    ]
    
    for type_data in initial_types:
        incident_type = IncidentType(name=type_data['name'], email_to=type_data['email_to'])
        db.session.add(incident_type)
    db.session.commit()

    # Add some initial personnel
    initial_personnel = ['John Smith', 'Jane Doe']
    for name in initial_personnel:
        person = Personnel(name=name)
        db.session.add(person)
    db.session.commit()

    print("Database has been reset and initialized with default data.")