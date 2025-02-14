from flask import render_template, redirect, url_for, flash, request, send_file, make_response
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, Incident, Personnel, IncidentType, EmailSettings, LoginLog
from app.email_utils import send_incident_email
import csv
from io import StringIO
from werkzeug.utils import secure_filename


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        success = False
        
        if user and user.check_password(request.form['password']):
            login_user(user)
            success = True
            
        # Log the login attempt
        log_entry = LoginLog(
            username=request.form.get('username', ''),
            success=success,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        if success:
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
    incidents = Incident.query.join(IncidentType, isouter=True) \
        .join(Personnel, isouter=True) \
        .order_by(Incident.timestamp.desc()).all()
    return render_template('dashboard.html', incidents=incidents)

@app.route('/report_incident', methods=['GET', 'POST'])
@login_required
def report_incident():
    personnel = Personnel.query.all()
    incident_types = IncidentType.query.all()
    
    if request.method == 'POST':
        incident_type = IncidentType.query.get(request.form['type_id'])
        reporter = Personnel.query.get(request.form['personnel_id'])
        
        incident = Incident(
            type_id=request.form['type_id'],
            type_name=incident_type.name,  # Store the type name
            reporter_name=reporter.name,    # Store the reporter name
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
            cell_number = request.form['cell_number']
            if name:
                personnel = Personnel(name=name, cell_number=cell_number)
                db.session.add(personnel)
                db.session.commit()
                flash('Personnel added successfully')
        elif 'update_cell' in request.form:
            personnel_id = request.form['personnel_id']
            cell_number = request.form['cell_number']
            personnel = Personnel.query.get(personnel_id)
            if personnel:
                personnel.cell_number = cell_number
                db.session.commit()
                flash('Contact information updated successfully')
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

@app.route('/admin/export_personnel')
@login_required
def export_personnel():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['name', 'cell_number'])  # Updated header
    
    personnel = Personnel.query.all()
    for person in personnel:
        writer.writerow([person.name, person.cell_number or ''])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=personnel.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/export_incident_types')
@login_required
def export_incident_types():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    # Create CSV in memory
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['name', 'email_to'])  # Header
    
    types = IncidentType.query.all()
    for type in types:
        writer.writerow([type.name, type.email_to])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=incident_types.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# Import routes
@app.route('/admin/import_personnel', methods=['POST'])
@login_required
def import_personnel():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        flash('No file provided')
        return redirect(url_for('manage_personnel'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('manage_personnel'))
    
    if not file.filename.endswith('.csv'):
        flash('Only CSV files are allowed')
        return redirect(url_for('manage_personnel'))
    
    try:
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        next(csv_input)  # Skip header row
        
        for row in csv_input:
            if len(row) >= 2:  # Check if row has both name and cell number
                name = row[0].strip()
                cell_number = row[1].strip() if len(row) > 1 else ''
                if name and not Personnel.query.filter_by(name=name).first():
                    person = Personnel(name=name, cell_number=cell_number)
                    db.session.add(person)
        
        db.session.commit()
        flash('Personnel imported successfully')
    except Exception as e:
        flash(f'Error importing file: {str(e)}')
    
    return redirect(url_for('manage_personnel'))

@app.route('/admin/import_incident_types', methods=['POST'])
@login_required
def import_incident_types():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if 'file' not in request.files:
        flash('No file provided')
        return redirect(url_for('manage_incident_types'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('manage_incident_types'))
    
    if not file.filename.endswith('.csv'):
        flash('Only CSV files are allowed')
        return redirect(url_for('manage_incident_types'))
    
    try:
        # Read CSV file
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        next(csv_input)  # Skip header row
        
        for row in csv_input:
            if len(row) >= 2:  # Check if row has name and email
                name = row[0].strip()
                email_to = row[1].strip()
                if name and not IncidentType.query.filter_by(name=name).first():
                    incident_type = IncidentType(name=name, email_to=email_to)
                    db.session.add(incident_type)
        
        db.session.commit()
        flash('Incident types imported successfully')
    except Exception as e:
        flash(f'Error importing file: {str(e)}')
    
    return redirect(url_for('manage_incident_types'))

@app.route('/admin/login_logs')
@login_required
def login_logs():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    # Get logs with pagination
    page = request.args.get('page', 1, type=int)
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    
    return render_template('admin/login_logs.html', logs=logs)