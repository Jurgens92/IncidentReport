from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, Incident, Personnel, IncidentType, EmailSettings
from app.email_utils import send_incident_email

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # This will eagerly load the related incident_type and reporter data
    incidents = Incident.query.join(IncidentType).join(Personnel).all()
    return render_template('dashboard.html', incidents=incidents)

@app.route('/report_incident', methods=['GET', 'POST'])
@login_required
def report_incident():
    personnel = Personnel.query.all()
    incident_types = IncidentType.query.all()
    
    if request.method == 'POST':
        incident = Incident(
            type_id=request.form['type_id'],
            description=request.form['description'],
            user_id=current_user.id,
            personnel_id=request.form['personnel_id']
        )
        db.session.add(incident)
        db.session.commit()
        
        # Send email notification
        send_incident_email(incident)
        
        return redirect(url_for('dashboard'))
        
    return render_template('incident_form.html', 
                         personnel=personnel,
                         incident_types=incident_types)

@app.route('/admin/personnel', methods=['GET', 'POST'])
@login_required
def manage_personnel():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'add_personnel' in request.form:
            name = request.form['name']
            if name:
                personnel = Personnel(name=name)
                db.session.add(personnel)
                db.session.commit()
                flash('Personnel added successfully')
        elif 'delete_personnel' in request.form:
            personnel_id = request.form['personnel_id']
            personnel = Personnel.query.get(personnel_id)
            if personnel:
                db.session.delete(personnel)
                db.session.commit()
                flash('Personnel deleted successfully')
    
    personnel_list = Personnel.query.all()
    return render_template('admin/personnel.html', personnel=personnel_list)

@app.route('/admin/incident_types', methods=['GET', 'POST'])
@login_required
def manage_incident_types():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'add_type' in request.form:
            name = request.form['name']
            email_to = request.form['email_to']
            if name:
                incident_type = IncidentType(name=name, email_to=email_to)
                db.session.add(incident_type)
                db.session.commit()
                flash('Incident type added successfully')
        elif 'update_email' in request.form:
            type_id = request.form['type_id']
            email_to = request.form['email_to']
            incident_type = IncidentType.query.get(type_id)
            if incident_type:
                incident_type.email_to = email_to
                db.session.commit()
                flash('Email updated successfully')
        elif 'delete_type' in request.form:
            type_id = request.form['type_id']
            incident_type = IncidentType.query.get(type_id)
            if incident_type:
                db.session.delete(incident_type)
                db.session.commit()
                flash('Incident type deleted successfully')
    
    incident_types = IncidentType.query.all()
    return render_template('admin/incident_types.html', incident_types=incident_types)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'add_user' in request.form:
            username = request.form['username']
            password = request.form['password']
            is_admin = 'is_admin' in request.form
            
            if username and password:
                user = User(username=username, is_admin=is_admin)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash('User added successfully')
        elif 'delete_user' in request.form:
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user and user != current_user:  # Prevent self-deletion
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully')
            else:
                flash('Cannot delete your own account')
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/email_settings', methods=['GET', 'POST'])
@login_required
def manage_email_settings():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    settings = EmailSettings.query.first()
    if not settings:
        settings = EmailSettings()
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.smtp_server = request.form['smtp_server']
        settings.smtp_port = int(request.form['smtp_port'])
        settings.smtp_username = request.form['smtp_username']
        if request.form['smtp_password']:  # Only update if new password provided
            settings.smtp_password = request.form['smtp_password']
        settings.from_address = request.form['from_address']
        db.session.commit()
        flash('Email settings updated successfully')
        
    return render_template('admin/email_settings.html', settings=settings)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('change_password'))
            
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/admin/change_user_password/<int:user_id>', methods=['POST'])
@login_required
def change_user_password(user_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        flash(f'Password updated for user {user.username}')
    
    return redirect(url_for('manage_users'))