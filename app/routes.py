from flask import render_template, redirect, url_for, flash, request, send_file, make_response
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, Incident, Personnel, IncidentType, EmailSettings, LoginLog, ActionLog, ResolutionHistory
from app.email_utils import send_incident_email, send_resolution_email
import csv
from io import StringIO
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import func, extract, case, and_


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
        
        # Enhanced IP address detection
        ip_address = None
        # Try X-Forwarded-For first
        if request.headers.getlist("X-Forwarded-For"):
            forwarded_ips = request.headers.getlist("X-Forwarded-For")[0].split(',')
            ip_address = forwarded_ips[0].strip()
        # Try X-Real-IP next
        elif request.headers.get("X-Real-IP"):
            ip_address = request.headers.get("X-Real-IP")
        # Fall back to remote_addr
        if not ip_address:
            ip_address = request.remote_addr
            
        # Log the login attempt
        log_entry = LoginLog(
            username=request.form.get('username', ''),
            success=success,
            ip_address=ip_address
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
@app.route('/dashboard/<filter_type>')
@login_required
def dashboard(filter_type='unresolved'):
    # Create base query
    query = Incident.query.join(IncidentType, isouter=True) \
        .join(Personnel, isouter=True)
    
    # Apply filter
    if filter_type == 'resolved':
        query = query.filter(Incident.resolution != None)
    elif filter_type == 'unresolved':
        query = query.filter(Incident.resolution == None)
    # 'all' filter doesn't need additional conditions
    
    # Get incidents with ordered by timestamp desc
    incidents = query.order_by(Incident.timestamp.desc()).all()
    
    return render_template('dashboard.html', incidents=incidents, current_filter=filter_type)

@app.route('/report_incident', methods=['GET', 'POST'])
@login_required
def report_incident():
    personnel = Personnel.query.all()
    incident_types = IncidentType.query.all()
    
    if request.method == 'POST':
        incident_type = IncidentType.query.get(request.form['type_id'])
        reporter = Personnel.query.get(request.form['personnel_id'])
        
        # Get IP address - reusing the same logic as in the login route
        ip_address = None
        if request.headers.getlist("X-Forwarded-For"):
            forwarded_ips = request.headers.getlist("X-Forwarded-For")[0].split(',')
            ip_address = forwarded_ips[0].strip()
        elif request.headers.get("X-Real-IP"):
            ip_address = request.headers.get("X-Real-IP")
        if not ip_address:
            ip_address = request.remote_addr
        
        incident = Incident(
            type_id=request.form['type_id'],
            type_name=incident_type.name,  # Store the type name
            reporter_name=reporter.name,    # Store the reporter name
            description=request.form['description'],
            user_id=current_user.id,
            personnel_id=request.form['personnel_id'],
            ip_address=ip_address  # Store the IP address
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

@app.route('/resolve_incident/<int:incident_id>', methods=['GET', 'POST'])
@login_required
def resolve_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    personnel = Personnel.query.all()  # Get all personnel for the dropdown
    
    # Check if already resolved
    if incident.resolution:
        return redirect(url_for('view_resolution', incident_id=incident_id))
    
    if request.method == 'POST':
        # Get selected personnel
        resolver_id = request.form.get('personnel_id')
        resolver = Personnel.query.get(resolver_id)
        
        # Update the incident with resolution details
        incident.resolution = request.form['resolution']
        incident.resolved_by = resolver.name  # Use the personnel name
        incident.resolved_timestamp = datetime.utcnow()
        incident.resolved_by_user_id = current_user.id
        
        db.session.commit()
        
        # Send email notification
        send_resolution_email(incident)
        
        flash('Incident has been resolved successfully')
        return redirect(url_for('dashboard'))
        
    return render_template('resolution_form.html', incident=incident, personnel=personnel)

@app.route('/view_resolution/<int:incident_id>')
@login_required
def view_resolution(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    # Check if the incident is resolved
    if not incident.resolution:
        flash('This incident has not been resolved yet')
        return redirect(url_for('dashboard'))
        
    return render_template('resolution_details.html', incident=incident)

@app.route('/unresolve_incident/<int:incident_id>', methods=['POST'])
@login_required
def unresolve_incident(incident_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
        
    incident = Incident.query.get_or_404(incident_id)
    
    # Check if the incident is resolved
    if not incident.resolution:
        flash('This incident is not marked as resolved')
        return redirect(url_for('dashboard'))
    
    # Save the current resolution to history
    resolution_history = ResolutionHistory(
        incident_id=incident.id,
        resolution_text=incident.resolution,
        resolved_by=incident.resolved_by,
        resolved_timestamp=incident.resolved_timestamp,
        resolved_by_user_id=incident.resolved_by_user_id,
        unresolve_timestamp=datetime.utcnow(),
        unresolved_by_user_id=current_user.id
    )
    db.session.add(resolution_history)
    
    # Log the action
    log_entry = ActionLog(
        incident_id=incident.id,
        user_id=current_user.id,
        action="Unresolve",
        details=f"Unmarked resolution that was entered by {incident.resolved_by}: {incident.resolution}"
    )
    db.session.add(log_entry)
    
    # Clear the resolution fields from the current incident
    incident.resolution = None
    incident.resolved_by = None
    incident.resolved_timestamp = None
    incident.resolved_by_user_id = None
    
    db.session.commit()
    
    flash('Incident has been marked as unresolved')
    return redirect(url_for('dashboard'))

@app.route('/resolution_history/<int:incident_id>')
@login_required
def resolution_history(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    history = ResolutionHistory.query.filter_by(incident_id=incident_id).order_by(ResolutionHistory.resolved_timestamp.desc()).all()
    
    # Get usernames for unresolved_by IDs
    for entry in history:
        if entry.unresolved_by_user_id:
            user = User.query.get(entry.unresolved_by_user_id)
            entry.unresolved_by_username = user.username if user else "Unknown User"
        else:
            entry.unresolved_by_username = "N/A"
    
    return render_template('resolution_history.html', incident=incident, history=history)

@app.route('/admin/delete_incident/<int:incident_id>', methods=['POST'])
@login_required
def delete_incident(incident_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    incident = Incident.query.get_or_404(incident_id)
    
    # Log the deletion
    log_entry = ActionLog(
        incident_id=incident.id,
        user_id=current_user.id,
        action="Delete",
        details=f"Deleted incident: {incident.type_name} reported by {incident.reporter_name}"
    )
    db.session.add(log_entry)
    
    # Delete the incident
    db.session.delete(incident)
    db.session.commit()
    
    flash('Incident deleted successfully')
    return redirect(url_for('dashboard'))

# Reporting

@app.route('/reports')
@login_required
def reports():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    # Summary statistics
    total_incidents = Incident.query.count()
    resolved_incidents = Incident.query.filter(Incident.resolution != None).count()
    unresolved_incidents = total_incidents - resolved_incidents
    recent_incidents = Incident.query.filter(
        Incident.timestamp >= datetime.utcnow() - timedelta(days=7)
    ).count()
    
    # Incidents by type
    type_counts = db.session.query(
        Incident.type_name, 
        func.count(Incident.id)
    ).group_by(Incident.type_name).all()
    
    # Recent incidents
    recent = Incident.query.order_by(Incident.timestamp.desc()).limit(5).all()
    
    # Monthly trend (last 6 months)
    monthly_data = []
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    
    for i in range(6):
        month = ((current_month - i - 1) % 12) + 1
        year = current_year if month <= current_month else current_year - 1
        
        count = Incident.query.filter(
            extract('month', Incident.timestamp) == month,
            extract('year', Incident.timestamp) == year
        ).count()
        
        month_name = datetime(year, month, 1).strftime('%b %Y')
        monthly_data.append({'month': month_name, 'count': count})
    
    monthly_data.reverse()
    
    # Get top reporters and resolvers
    top_reporters = db.session.query(
        Incident.reporter_name,
        func.count(Incident.id).label('count')
    ).group_by(Incident.reporter_name).order_by(func.count(Incident.id).desc()).limit(5).all()
    
    top_resolvers = db.session.query(
        Incident.resolved_by,
        func.count(Incident.id).label('count')
    ).filter(Incident.resolved_by != None).group_by(Incident.resolved_by).order_by(
        func.count(Incident.id).desc()
    ).limit(5).all()
    
    return render_template('reports.html',
                          total_incidents=total_incidents,
                          resolved_incidents=resolved_incidents,
                          unresolved_incidents=unresolved_incidents,
                          recent_incidents=recent_incidents,
                          type_counts=type_counts,
                          recent=recent,
                          monthly_data=monthly_data,
                          top_reporters=top_reporters,
                          top_resolvers=top_resolvers)

@app.route('/reports/export')
@login_required
def export_reports():

    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))

    # Get optional filter from query parameter
    filter_type = request.args.get('filter', 'all')
    
    query = Incident.query
    
    # Apply filters
    if filter_type == 'unresolved':
        query = query.filter(Incident.resolution == None)
    elif filter_type == 'resolved':
        query = query.filter(Incident.resolution != None)
    elif filter_type == 'recent':
        query = query.filter(Incident.timestamp >= datetime.utcnow() - timedelta(days=30))
    
    incidents = query.order_by(Incident.timestamp.desc()).all()
    
    # Create CSV in memory
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        'ID', 'Date/Time', 'Type', 'Reporter', 'Description', 
        'Status', 'Resolved By', 'Resolution Date', 'Resolution'
    ])
    
    for incident in incidents:
        writer.writerow([
            incident.id,
            incident.timestamp.strftime('%Y-%m-%d %H:%M'),
            incident.type_name,
            incident.reporter_name,
            incident.description,
            'Resolved' if incident.resolution else 'Unresolved',
            incident.resolved_by or '',
            incident.resolved_timestamp.strftime('%Y-%m-%d %H:%M') if incident.resolved_timestamp else '',
            incident.resolution or ''
        ])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=incidents_{filter_type}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/reports/detailed')
@login_required
def detailed_reports():

    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))

    # Get filter parameters
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    status = request.args.get('status')
    type_id = request.args.get('type_id')
    
    # Default date range (last 30 days)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    if start_date_str and end_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)  # Add a day to make inclusive
    
    # Build query with filters
    query = Incident.query.filter(
        Incident.timestamp >= start_date,
        Incident.timestamp <= end_date
    )
    
    if status == 'resolved':
        query = query.filter(Incident.resolution != None)
    elif status == 'unresolved':
        query = query.filter(Incident.resolution == None)
    
    if type_id and type_id.isdigit():
        query = query.filter(Incident.type_id == int(type_id))
    
    # Get incidents and incident types for filter dropdown
    incidents = query.order_by(Incident.timestamp.desc()).all()
    incident_types = IncidentType.query.all()
    
    # Calculate some statistics for the filtered results
    stats = {
        'total': len(incidents),
        'resolved': sum(1 for i in incidents if i.resolution),
        'unresolved': sum(1 for i in incidents if not i.resolution),
        'avg_resolution_hours': 0
    }
    
    # Calculate average resolution time
    resolution_times = []
    for incident in incidents:
        if incident.resolution and incident.resolved_timestamp:
            hours = (incident.resolved_timestamp - incident.timestamp).total_seconds() / 3600
            resolution_times.append(hours)
    
    if resolution_times:
        stats['avg_resolution_hours'] = round(sum(resolution_times) / len(resolution_times), 1)
    
    return render_template('detailed_reports.html',
                          incidents=incidents,
                          incident_types=incident_types,
                          start_date=start_date,
                          end_date=end_date - timedelta(days=1),  # Adjust for display
                          selected_status=status,
                          selected_type=type_id,
                          stats=stats)