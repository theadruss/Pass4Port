from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime, timedelta
import uuid
import hashlib
import os
import base64
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage (replace with database in production)
users = {
    'visitor': {'password': 'password', 'role': 'visitor', 'name': 'Rahul Sharma', 'id': 'VIS-2024-001234'},
    'officer': {'password': 'password', 'role': 'officer', 'name': 'Dr. Rajesh Kumar', 'id': 'OFF-2024-001'},
    'security': {'password': 'password', 'role': 'security', 'name': 'Suresh Gupta', 'id': 'SEC-001'},
    'admin': {'password': 'password', 'role': 'admin', 'name': 'System Administrator', 'id': 'ADMIN-001'}
}

# Store pending officer registrations
pending_officer_registrations = {}

# Other existing data structures
visit_requests = [
    {
        'id': 'VR-2024-001',
        'visitor_name': 'Rahul Sharma',
        'visitor_id': 'VIS-2024-001234',
        'department': 'Ministry of External Affairs',
        'date': '2024-01-15',
        'time': '10:00 AM',
        'purpose': 'Document Submission',
        'status': 'approved',
        'officer': 'Dr. Rajesh Kumar',
        'submitted_on': '2024-01-14'
    }
]

entry_logs = [
    {
        'id': 'PASS-2024-001',
        'visitor_name': 'Rahul Sharma',
        'department': 'Ministry of External Affairs',
        'entry_time': '09:30 AM',
        'exit_time': None,
        'status': 'inside'
    }
]

flagged_ids = ['XXXX-XXXX-1111', 'XXXX-XXXX-2222']

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    """Hash a password for storing."""
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

def check_password(hashed_password, user_password):
    """Verify a stored password against one provided by user"""
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')
    user_type = request.form.get('userType')
    
    # Check if user exists in pending registrations
    if username in pending_officer_registrations:
        flash('Your account is pending approval. Please wait for admin approval.', 'info')
        return redirect(url_for('login'))
    
    # Check if user exists and credentials match
    if username in users:
        user = users[username]
        # In production, use: if check_password(user['password'], password)
        if user['password'] == password and user['role'] == user_type:
            session['user'] = username
            session['role'] = user_type
            session['name'] = user['name']
            session['user_id'] = user['id']
            return redirect(url_for(f'dashboard_{user_type}'))
    
    flash('Invalid credentials or user type mismatch', 'error')
    return redirect(url_for('login'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def handle_register():
    try:
        logger.debug("Registration request received")
        logger.debug(f"Form data: {request.form}")
        logger.debug(f"Files: {request.files}")
        
        # Get all form data
        full_name = request.form.get('fullName', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        
        logger.debug(f"Extracted data - Name: {full_name}, Role: {role}, Username: {username}")
        
        # Validate required fields
        if not all([full_name, phone, email, username, password, role]):
            missing_fields = []
            if not full_name: missing_fields.append('Full Name')
            if not phone: missing_fields.append('Phone')
            if not email: missing_fields.append('Email')
            if not username: missing_fields.append('Username')
            if not password: missing_fields.append('Password')
            if not role: missing_fields.append('Role')
            
            logger.error(f"Missing required fields: {missing_fields}")
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
            
        # Check if username exists
        if username in users or username in pending_officer_registrations:
            logger.error(f"Username {username} already exists")
            return jsonify({
                'success': False,
                'message': 'Username already exists'
            }), 400
        
        # Handle file uploads - make them optional for testing
        aadhaar_file = handle_file_upload('aadhaarFile')
        photo_file = handle_photo_upload(request.form.get('photoData'))
        
        # For debugging - make file uploads optional
        if not aadhaar_file:
            logger.warning("No Aadhaar file uploaded, using placeholder")
            aadhaar_file = "placeholder_aadhaar.jpg"
            
        if not photo_file:
            logger.warning("No photo captured, using placeholder")
            photo_file = "placeholder_photo.jpg"
        
        logger.debug(f"Files processed - Aadhaar: {aadhaar_file}, Photo: {photo_file}")
        
        # Generate user ID
        user_id = generate_user_id(role)
        logger.debug(f"Generated user ID: {user_id}")
        
        # Create user data
        user_data = {
            'password': password,
            'role': role,
            'name': full_name,
            'id': user_id,
            'phone': phone,
            'email': email,
            'aadhaar_file': aadhaar_file,
            'photo_file': photo_file,
            'registration_date': datetime.now().strftime('%Y-%m-%d'),
            'status': 'active'
        }
        
        # Process registration based on role
        if role in ['officer', 'admin', 'security']:
            user_data['status'] = 'pending'
            pending_officer_registrations[username] = user_data
            logger.info(f"Added {username} to pending registrations")
            
            return jsonify({
                'success': True,
                'message': 'Registration submitted for admin approval',
                'user_id': user_id,
                'status': 'pending'
            })
        else:
            # For visitors, activate immediately
            users[username] = user_data
            logger.info(f"Registered visitor {username} successfully")
            
            return jsonify({
                'success': True,
                'message': 'Registration successful! You can now login.',
                'user_id': user_id,
                'status': 'active'
            })
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Registration failed: {str(e)}'
        }), 500

def handle_file_upload(field_name):
    """Handle file upload and return filename if successful"""
    try:
        if field_name not in request.files:
            logger.debug(f"No file field {field_name} in request")
            return None
            
        file = request.files[field_name]
        if not file or file.filename == '':
            logger.debug(f"No file selected for {field_name}")
            return None
            
        if not allowed_file(file.filename):
            logger.error(f"File type not allowed for {file.filename}")
            return None
            
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        logger.debug(f"File saved successfully: {unique_filename}")
        return unique_filename
        
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        return None

def handle_photo_upload(photo_data):
    """Handle photo data URL and return filename if successful"""
    try:
        if not photo_data:
            logger.debug("No photo data provided")
            return None
            
        if not photo_data.startswith('data:image/'):
            logger.debug("Invalid photo data format")
            return None
            
        # Handle different image formats
        if 'data:image/png;base64,' in photo_data:
            photo_data = photo_data.replace('data:image/png;base64,', '')
            extension = 'png'
        elif 'data:image/jpeg;base64,' in photo_data:
            photo_data = photo_data.replace('data:image/jpeg;base64,', '')
            extension = 'jpg'
        else:
            logger.error("Unsupported image format in photo data")
            return None
            
        photo_filename = f"{uuid.uuid4().hex}_photo.{extension}"
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
        
        with open(photo_path, "wb") as f:
            f.write(base64.b64decode(photo_data))
            
        logger.debug(f"Photo saved successfully: {photo_filename}")
        return photo_filename
        
    except Exception as e:
        logger.error(f"Photo upload error: {str(e)}")
        return None

def generate_user_id(role):
    """Generate user ID based on role"""
    year = datetime.now().year
    random_id = str(uuid.uuid4())[:6].upper()
    
    if role == 'visitor':
        return f"VIS-{year}-{random_id}"
    elif role == 'officer':
        return f"OFF-{year}-{random_id[:4]}"
    elif role == 'security':
        return f"SEC-{random_id}"
    elif role == 'admin':
        return f"ADM-{random_id}"
    else:
        return f"USER-{random_id}"

@app.route('/approve_registration/<username>')
def approve_registration(username):
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if username in pending_officer_registrations:
        user_data = pending_officer_registrations[username]
        user_data['status'] = 'active'
        
        # Add to active users
        users[username] = user_data
        del pending_officer_registrations[username]
        
        flash(f'Registration for {username} approved', 'success')
    else:
        flash('Registration not found', 'error')
    
    return redirect(url_for('dashboard_admin'))

@app.route('/reject_registration/<username>')
def reject_registration(username):
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if username in pending_officer_registrations:
        del pending_officer_registrations[username]
        flash(f'Registration for {username} rejected', 'success')
    else:
        flash('Registration not found', 'error')
    
    return redirect(url_for('dashboard_admin'))

# Dashboard routes (visitor, officer, security, admin)
@app.route('/dashboard/visitor')
def dashboard_visitor():
    if 'user' not in session or session['role'] != 'visitor':
        return redirect(url_for('login'))
    
    user_requests = [req for req in visit_requests if req['visitor_id'] == session['user_id']]
    return render_template('dashboard_visitor.html', requests=user_requests)

@app.route('/dashboard/officer')
def dashboard_officer():
    if 'user' not in session or session['role'] != 'officer':
        return redirect(url_for('login'))
    
    pending_requests = [req for req in visit_requests if req['status'] == 'pending']
    approved_requests = [req for req in visit_requests if req['status'] == 'approved']
    
    return render_template('dashboard_officer.html', 
                         pending_requests=pending_requests,
                         approved_requests=approved_requests)

@app.route('/dashboard/security')
def dashboard_security():
    if 'user' not in session or session['role'] != 'security':
        return redirect(url_for('login'))
    
    return render_template('dashboard_security.html', entry_logs=entry_logs)

@app.route('/dashboard/admin')
def dashboard_admin():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    stats = {
        'total_users': len(users),
        'active_visitors': len([log for log in entry_logs if log['status'] == 'inside']),
        'pending_approvals': len(pending_officer_registrations),
        'flagged_ids': len(flagged_ids)
    }
    
    return render_template('dashboard_admin.html', 
                         stats=stats, 
                         flagged_ids=flagged_ids,
                         pending_registrations=pending_officer_registrations)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Debug route to check registrations
@app.route('/debug/users')
def debug_users():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    return jsonify({
        'active_users': users,
        'pending_registrations': pending_officer_registrations
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
