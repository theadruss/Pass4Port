from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from datetime import datetime, timedelta
import uuid
import hashlib
import os
import base64
import sqlite3
import re
import json
import numpy as np
import cv2
from io import BytesIO
from werkzeug.utils import secure_filename
import logging
import time
from PIL import Image
import tempfile

# Import DeepFace for face recognition
try:
    from deepface import DeepFace
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    print("DeepFace not available. Face recognition will be disabled.")
    FACE_RECOGNITION_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max upload
app.config['DATABASE'] = 'visitor_management.db'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/images', exist_ok=True)

# Database setup
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT NOT NULL,
        user_id TEXT UNIQUE NOT NULL,
        phone TEXT,
        email TEXT,
        aadhaar TEXT,
        photo_file TEXT,
        registration_date TEXT,
        status TEXT DEFAULT 'active'
    )
    ''')
    
    # Create visit_requests table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS visit_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE NOT NULL,
        visitor_name TEXT NOT NULL,
        visitor_id TEXT NOT NULL,
        department TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        purpose TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        officer TEXT,
        remarks TEXT,
        submitted_on TEXT NOT NULL
    )
    ''')
    
    # Create entry_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS entry_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_id TEXT UNIQUE NOT NULL,
        visitor_name TEXT NOT NULL,
        visitor_id TEXT NOT NULL,
        department TEXT NOT NULL,
        aadhaar TEXT,
        entry_time TEXT NOT NULL,
        exit_time TEXT,
        status TEXT DEFAULT 'inside',
        entry_photo TEXT,
        face_match_score REAL
    )
    ''')
    
    # Create flagged_aadhaar table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS flagged_aadhaar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        aadhaar TEXT UNIQUE NOT NULL,
        reason TEXT,
        added_by TEXT,
        added_on TEXT NOT NULL
    )
    ''')
    
    # Create notifications table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )
    ''')
    
    # Create user_settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        email_notifications INTEGER DEFAULT 1,
        sms_notifications INTEGER DEFAULT 0,
        theme TEXT DEFAULT 'light',
        language TEXT DEFAULT 'en',
        dashboard_widgets TEXT
    )
    ''')
    
    # Insert default users if they don't exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('visitor', 'password', 'visitor', 'Rahul Sharma', 'VIS-2024-001234', '+91 9876543210', 'rahul@example.com', '123456789012', 'placeholder.jpg', '2024-01-01', 'active'),
            ('officer', 'password', 'officer', 'Dr. Rajesh Kumar', 'OFF-2024-001', '+91 9876543211', 'rajesh@example.com', None, 'placeholder.jpg', '2024-01-01', 'active'),
            ('security', 'password', 'security', 'Suresh Gupta', 'SEC-001', '+91 9876543212', 'suresh@example.com', None, 'placeholder.jpg', '2024-01-01', 'active'),
            ('admin', 'password', 'admin', 'System Administrator', 'ADMIN-001', '+91 9876543213', 'admin@example.com', None, 'placeholder.jpg', '2024-01-01', 'active')
        ]
        cursor.executemany('''
        INSERT INTO users (username, password, role, name, user_id, phone, email, aadhaar, photo_file, registration_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_users)
    
    # Insert default visit requests if they don't exist
    cursor.execute("SELECT COUNT(*) FROM visit_requests")
    if cursor.fetchone()[0] == 0:
        default_requests = [
            ('VR-2024-001', 'Rahul Sharma', 'VIS-2024-001234', 'Ministry of External Affairs', '2024-01-15', '10:00 AM', 'Document Submission', 'approved', 'Dr. Rajesh Kumar', None, '2024-01-14'),
            ('VR-2024-002', 'Rahul Sharma', 'VIS-2024-001234', 'Ministry of Home Affairs', '2024-01-20', '11:30 AM', 'Visa Consultation', 'pending', 'Mrs. Priya Sharma', None, '2024-01-18')
        ]
        cursor.executemany('''
        INSERT INTO visit_requests (request_id, visitor_name, visitor_id, department, date, time, purpose, status, officer, remarks, submitted_on)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_requests)
    
    # Insert default entry logs if they don't exist
    cursor.execute("SELECT COUNT(*) FROM entry_logs")
    if cursor.fetchone()[0] == 0:
        default_logs = [
            ('PASS-2024-001', 'Rahul Sharma', 'VIS-2024-001234', 'Ministry of External Affairs', '123456789012', '09:30 AM', None, 'inside', None, None)
        ]
        cursor.executemany('''
        INSERT INTO entry_logs (pass_id, visitor_name, visitor_id, department, aadhaar, entry_time, exit_time, status, entry_photo, face_match_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_logs)
    
    # Insert default flagged Aadhaar numbers if they don't exist
    cursor.execute("SELECT COUNT(*) FROM flagged_aadhaar")
    if cursor.fetchone()[0] == 0:
        default_flagged = [
            ('111122223333', 'Security concern', 'admin', datetime.now().strftime('%Y-%m-%d')),
            ('444455556666', 'Blacklisted visitor', 'admin', datetime.now().strftime('%Y-%m-%d'))
        ]
        cursor.executemany('''
        INSERT INTO flagged_aadhaar (aadhaar, reason, added_by, added_on)
        VALUES (?, ?, ?, ?)
        ''', default_flagged)
    
    # Insert default notifications if they don't exist
    cursor.execute("SELECT COUNT(*) FROM notifications")
    if cursor.fetchone()[0] == 0:
        default_notifications = [
            ('VIS-2024-001234', 'Visit Request Approved', 'Your visit request for Ministry of External Affairs has been approved.', 'success', 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('OFF-2024-001', 'New Visit Request', 'A new visit request requires your approval.', 'info', 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('SEC-001', 'Security Alert', 'A blacklisted visitor attempted to enter the facility.', 'warning', 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('ADMIN-001', 'System Update', 'The system has been updated to version 2.0.', 'info', 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        ]
        cursor.executemany('''
        INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', default_notifications)
    
    # Insert default user settings if they don't exist
    cursor.execute("SELECT COUNT(*) FROM user_settings")
    if cursor.fetchone()[0] == 0:
        default_settings = [
            ('VIS-2024-001234', 1, 0, 'light', 'en', json.dumps(['visits', 'profile', 'notifications'])),
            ('OFF-2024-001', 1, 1, 'light', 'en', json.dumps(['pending_requests', 'approved_requests', 'calendar'])),
            ('SEC-001', 1, 1, 'dark', 'en', json.dumps(['active_visitors', 'recent_entries', 'security_alerts'])),
            ('ADMIN-001', 1, 1, 'dark', 'en', json.dumps(['system_stats', 'user_management', 'security_logs']))
        ]
        cursor.executemany('''
        INSERT INTO user_settings (user_id, email_notifications, sms_notifications, theme, language, dashboard_widgets)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', default_settings)
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

def allowed_file(filename):
    """Check if file extension is allowed"""
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

def validate_aadhaar(aadhaar):
    """Validate Aadhaar number format (12 digits)"""
    if not aadhaar:
        return False
    # Remove any spaces or dashes
    aadhaar = aadhaar.replace(' ', '').replace('-', '')
    # Check if it's 12 digits
    return bool(re.match(r'^\d{12}$', aadhaar))

def mask_aadhaar(aadhaar):
    """Mask Aadhaar number for display (e.g., XXXX-XXXX-1234)"""
    if not aadhaar:
        return "Not provided"
    # Remove any spaces or dashes
    aadhaar = aadhaar.replace(' ', '').replace('-', '')
    # Return masked version
    if len(aadhaar) == 12:
        return f"XXXX-XXXX-{aadhaar[-4:]}"
    return "Invalid format"

def is_aadhaar_blacklisted(aadhaar):
    """Check if Aadhaar number is blacklisted"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM flagged_aadhaar WHERE aadhaar = ?", (aadhaar,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def get_blacklist_reason(aadhaar):
    """Get the reason why an Aadhaar number is blacklisted"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT reason FROM flagged_aadhaar WHERE aadhaar = ?", (aadhaar,))
    result = cursor.fetchone()
    conn.close()
    return result['reason'] if result else "Unknown reason"

def compare_faces(known_image_path, unknown_image_data):
    """Compare faces using DeepFace"""
    if not FACE_RECOGNITION_AVAILABLE:
        logger.warning("Face recognition is not available. Skipping face comparison.")
        return 0.5  # Return a neutral score
    
    try:
        # Check if known image exists
        if not os.path.exists(known_image_path):
            logger.error(f"Known image not found: {known_image_path}")
            return 0.0
        
        # Process the unknown image from base64 data
        if unknown_image_data.startswith('data:image/'):
            # Extract the base64 encoded image
            image_data = unknown_image_data.split(',')[1]
            image_bytes = base64.b64decode(image_data)
            
            # Save to a temporary file
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(image_bytes)
            
            try:
                # Use DeepFace to verify
                result = DeepFace.verify(
                    img1_path=known_image_path,
                    img2_path=temp_file_path,
                    enforce_detection=False,
                    model_name="VGG-Face"
                )
                
                # Clean up temporary file
                os.unlink(temp_file_path)
                
                # Extract verification result
                if result["verified"]:
                    # Convert distance to similarity (0 to 1, where 1 is perfect match)
                    # DeepFace distance is typically between 0 and 1, where lower is better
                    similarity = 1.0 - min(result["distance"], 1.0)
                    return similarity
                else:
                    return 0.0
                
            except Exception as e:
                logger.error(f"Error in DeepFace verification: {str(e)}")
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                return 0.0
        else:
            logger.error("Invalid image data format")
            return 0.0
    except Exception as e:
        logger.error(f"Error comparing faces: {str(e)}")
        return 0.0

def get_user_notifications(user_id, limit=5):
    """Get notifications for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM notifications 
    WHERE user_id = ? 
    ORDER BY created_at DESC, is_read ASC
    LIMIT ?
    """, (user_id, limit))
    notifications = cursor.fetchall()
    conn.close()
    return notifications

def get_unread_notification_count(user_id):
    """Get count of unread notifications for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def add_notification(user_id, title, message, notification_type='info'):
    """Add a notification for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO notifications (user_id, title, message, type, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (user_id, title, message, notification_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

def get_user_settings(user_id):
    """Get user settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_settings WHERE user_id = ?", (user_id,))
    settings = cursor.fetchone()
    conn.close()
    
    if settings:
        # Parse JSON fields
        if settings['dashboard_widgets']:
            try:
                settings = dict(settings)
                settings['dashboard_widgets'] = json.loads(settings['dashboard_widgets'])
            except:
                settings['dashboard_widgets'] = []
        return settings
    
    # Return default settings if not found
    return {
        'user_id': user_id,
        'email_notifications': 1,
        'sms_notifications': 0,
        'theme': 'light',
        'language': 'en',
        'dashboard_widgets': []
    }

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')
    user_type = request.form.get('userType')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user exists and credentials match
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # In production, use: if check_password(user['password'], password)
        if user['password'] == password and user['role'] == user_type:
            if user['status'] == 'pending':
                flash('Your account is pending approval. Please wait for admin approval.', 'info')
                return redirect(url_for('login'))
            
            session['user'] = username
            session['role'] = user_type
            session['name'] = user['name']
            session['user_id'] = user['user_id']
            
            # Add login notification
            add_notification(
                user['user_id'],
                'Login Successful',
                f'You logged in at {datetime.now().strftime("%H:%M:%S")} on {datetime.now().strftime("%Y-%m-%d")}',
                'info'
            )
            
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
        
        # Get all form data
        full_name = request.form.get('fullName', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        aadhaar = request.form.get('aadhaar', '').strip()
        
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
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            logger.error(f"Username {username} already exists")
            return jsonify({
                'success': False,
                'message': 'Username already exists'
            }), 400
        
        # Validate Aadhaar number for visitors
        if role == 'visitor':
            if not aadhaar:
                conn.close()
                logger.error("Aadhaar number is required for visitors")
                return jsonify({
                    'success': False,
                    'message': 'Aadhaar number is required for visitors'
                }), 400
                
            if not validate_aadhaar(aadhaar):
                conn.close()
                logger.error(f"Invalid Aadhaar number format")
                return jsonify({
                    'success': False,
                    'message': 'Please enter a valid 12-digit Aadhaar number'
                }), 400
            
            # Check if Aadhaar is blacklisted
            if is_aadhaar_blacklisted(aadhaar):
                reason = get_blacklist_reason(aadhaar)
                conn.close()
                logger.error(f"Blacklisted Aadhaar number detected: {reason}")
                return jsonify({
                    'success': False,
                    'message': f'Registration not allowed. Reason: {reason}. Please contact the administrator.'
                }), 400
        
        # Handle photo upload
        photo_file = handle_photo_upload(request.form.get('photoData'))
        
        # For debugging - make file uploads optional
        if not photo_file:
            logger.warning("No photo captured, using placeholder")
            photo_file = "placeholder.jpg"
        
        # Generate user ID
        user_id = generate_user_id(role)
        logger.debug(f"Generated user ID: {user_id}")
        
        # Process registration based on role
        status = 'active' if role == 'visitor' else 'pending'
        
        # Insert user into database
        cursor.execute('''
        INSERT INTO users (username, password, role, name, user_id, phone, email, aadhaar, photo_file, registration_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            username, 
            password,  # In production, use hash_password(password)
            role,
            full_name,
            user_id,
            phone,
            email,
            aadhaar if role == 'visitor' else None,
            photo_file,
            datetime.now().strftime('%Y-%m-%d'),
            status
        ))
        
        # Create default user settings
        cursor.execute('''
        INSERT INTO user_settings (user_id, email_notifications, sms_notifications, theme, language, dashboard_widgets)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            1,
            0,
            'light',
            'en',
            json.dumps(['profile', 'notifications'])
        ))
        
        conn.commit()
        conn.close()
        
        # Add notification for admin about new registration
        if status == 'pending':
            add_notification(
                'ADMIN-001',
                'New Registration',
                f'New {role} registration: {full_name} ({user_id}) requires approval',
                'info'
            )
        
        logger.info(f"Registered {role} {username} successfully with status {status}")
        
        return jsonify({
            'success': True,
            'message': 'Registration submitted for admin approval' if status == 'pending' else 'Registration successful! You can now login.',
            'user_id': user_id,
            'status': status
        })
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Registration failed: {str(e)}'
        }), 500

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
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute("SELECT * FROM users WHERE username = ? AND status = 'pending'", (username,))
    user = cursor.fetchone()
    
    if user:
        # Update user status
        cursor.execute("UPDATE users SET status = 'active' WHERE username = ?", (username,))
        
        # Add notification for the approved user
        add_notification(
            user['user_id'],
            'Registration Approved',
            'Your registration has been approved. You can now log in to the system.',
            'success'
        )
        
        flash(f'Registration for {username} approved', 'success')
    else:
        flash('Registration not found or already approved', 'error')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard_admin'))

@app.route('/reject_registration/<username>')
def reject_registration(username):
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute("SELECT * FROM users WHERE username = ? AND status = 'pending'", (username,))
    user = cursor.fetchone()
    
    if user:
        # Delete user
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        flash(f'Registration for {username} rejected', 'success')
    else:
        flash('Registration not found', 'error')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard_admin'))

# Dashboard routes (visitor, officer, security, admin)
@app.route('/dashboard/visitor')
def dashboard_visitor():
    if 'user' not in session or session['role'] != 'visitor':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user data including Aadhaar
    cursor.execute("SELECT * FROM users WHERE username = ?", (session['user'],))
    user = cursor.fetchone()
    
    # Get user requests
    cursor.execute("SELECT * FROM visit_requests WHERE visitor_id = ? ORDER BY submitted_on DESC", (session['user_id'],))
    requests = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    conn.close()
    
    masked_aadhaar = mask_aadhaar(user['aadhaar']) if user else "Not provided"
    
    return render_template('dashboard_visitor.html', 
                          requests=requests,
                          masked_aadhaar=masked_aadhaar,
                          notifications=notifications,
                          unread_count=unread_count,
                          settings=settings)

@app.route('/dashboard/officer')
def dashboard_officer():
    if 'user' not in session or session['role'] != 'officer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get pending requests
    cursor.execute("SELECT * FROM visit_requests WHERE status = 'pending' ORDER BY date ASC")
    pending_requests = cursor.fetchall()
    
    # Get approved requests
    cursor.execute("SELECT * FROM visit_requests WHERE status = 'approved' AND officer = ? ORDER BY date DESC", (session['name'],))
    approved_requests = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    conn.close()
    
    return render_template('dashboard_officer.html', 
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings,
                         now=datetime.now)

@app.route('/dashboard/security')
def dashboard_security():
    if 'user' not in session or session['role'] != 'security':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get entry logs
    cursor.execute("SELECT * FROM entry_logs ORDER BY entry_time DESC")
    entry_logs = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    conn.close()
    
    # Add masked Aadhaar to entry logs for display
    entry_logs_with_masked = []
    for log in entry_logs:
        log_dict = dict(log)
        if log['aadhaar']:
            log_dict['masked_aadhaar'] = mask_aadhaar(log['aadhaar'])
        else:
            log_dict['masked_aadhaar'] = "Not provided"
        entry_logs_with_masked.append(log_dict)
    
    return render_template('dashboard_security.html', 
                         entry_logs=entry_logs_with_masked,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings)

@app.route('/dashboard/admin')
def dashboard_admin():
    if 'user' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM entry_logs WHERE status = 'inside'")
    active_visitors = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'")
    pending_approvals = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM flagged_aadhaar")
    flagged_ids = cursor.fetchone()[0]
    
    # Get pending registrations
    cursor.execute("SELECT * FROM users WHERE status = 'pending'")
    pending_registrations = cursor.fetchall()
    
    # Get flagged Aadhaar numbers
    cursor.execute("SELECT * FROM flagged_aadhaar ORDER BY added_on DESC")
    flagged_aadhaar = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'active_visitors': active_visitors,
        'pending_approvals': pending_approvals,
        'flagged_ids': flagged_ids
    }
    
    return render_template('dashboard_admin.html', 
                         stats=stats, 
                         flagged_aadhaar=flagged_aadhaar,
                         pending_registrations=pending_registrations,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings)

@app.route('/logout')
def logout():
    if 'user' in session:
        # Add logout notification
        add_notification(
            session['user_id'],
            'Logout Successful',
            f'You logged out at {datetime.now().strftime("%H:%M:%S")} on {datetime.now().strftime("%Y-%m-%d")}',
            'info'
        )
    
    session.clear()
    return redirect(url_for('login'))

# API routes for visit requests
@app.route('/api/submit_request', methods=['POST'])
def submit_request():
    if 'user' not in session or session['role'] != 'visitor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    
    if not all([data.get('department'), data.get('date'), data.get('time'), data.get('purpose')]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get visitor information
    cursor.execute("SELECT name FROM users WHERE username = ?", (session['user'],))
    visitor = cursor.fetchone()
    
    if not visitor:
        conn.close()
        return jsonify({'success': False, 'message': 'Visitor not found'}), 404
    
    # Generate request ID
    request_id = f"VR-{datetime.now().year}-{str(uuid.uuid4())[:6].upper()}"
    
    # Insert visit request
    cursor.execute('''
    INSERT INTO visit_requests (request_id, visitor_name, visitor_id, department, date, time, purpose, status, officer, submitted_on)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request_id,
        visitor['name'],
        session['user_id'],
        data.get('department'),
        data.get('date'),
        data.get('time'),
        data.get('purpose'),
        'pending',
        data.get('officer', 'To be assigned'),
        datetime.now().strftime('%Y-%m-%d')
    ))
    
    # Add notification for officers
    cursor.execute("SELECT user_id FROM users WHERE role = 'officer'")
    officers = cursor.fetchall()
    
    for officer in officers:
        add_notification(
            officer['user_id'],
            'New Visit Request',
            f'New visit request from {visitor["name"]} for {data.get("department")} on {data.get("date")}',
            'info'
        )
    
    conn.commit()
    conn.close()
    
    # Add notification for visitor
    add_notification(
        session['user_id'],
        'Visit Request Submitted',
        f'Your visit request for {data.get("department")} on {data.get("date")} has been submitted and is pending approval.',
        'info'
    )
    
    return jsonify({
        'success': True,
        'message': 'Visit request submitted successfully',
        'request_id': request_id
    })

@app.route('/api/approve_request', methods=['POST'])
def approve_request():
    if 'user' not in session or session['role'] != 'officer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    request_id = request.json.get('request_id')
    
    if not request_id:
        return jsonify({'success': False, 'message': 'Request ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get request details
    cursor.execute("SELECT * FROM visit_requests WHERE request_id = ?", (request_id,))
    visit_request = cursor.fetchone()
    
    if not visit_request:
        conn.close()
        return jsonify({'success': False, 'message': 'Request not found'}), 404
    
    # Update request status
    cursor.execute("UPDATE visit_requests SET status = 'approved', officer = ? WHERE request_id = ?", 
                  (session['name'], request_id))
    
    conn.commit()
    conn.close()
    
    # Add notification for visitor
    add_notification(
        visit_request['visitor_id'],
        'Visit Request Approved',
        f'Your visit request for {visit_request["department"]} on {visit_request["date"]} has been approved.',
        'success'
    )
    
    return jsonify({
        'success': True,
        'message': 'Visit request approved successfully'
    })

@app.route('/api/reject_request', methods=['POST'])
def reject_request():
    if 'user' not in session or session['role'] != 'officer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    request_id = data.get('request_id')
    remarks = data.get('remarks', 'No remarks provided')
    
    if not request_id:
        return jsonify({'success': False, 'message': 'Request ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get request details
    cursor.execute("SELECT * FROM visit_requests WHERE request_id = ?", (request_id,))
    visit_request = cursor.fetchone()
    
    if not visit_request:
        conn.close()
        return jsonify({'success': False, 'message': 'Request not found'}), 404
    
    # Update request status
    cursor.execute("UPDATE visit_requests SET status = 'rejected', officer = ?, remarks = ? WHERE request_id = ?", 
                  (session['name'], remarks, request_id))
    
    conn.commit()
    conn.close()
    
    # Add notification for visitor
    add_notification(
        visit_request['visitor_id'],
        'Visit Request Rejected',
        f'Your visit request for {visit_request["department"]} on {visit_request["date"]} has been rejected. Reason: {remarks}',
        'error'
    )
    
    return jsonify({
        'success': True,
        'message': 'Visit request rejected successfully'
    })

# API routes for security operations
@app.route('/api/verify_visitor', methods=['POST'])
def verify_visitor():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    aadhaar = data.get('aadhaar')
    photo_data = data.get('photoData')
    
    if not aadhaar:
        return jsonify({'success': False, 'message': 'Aadhaar number is required'}), 400
    
    if not validate_aadhaar(aadhaar):
        return jsonify({'success': False, 'message': 'Invalid Aadhaar number format'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if Aadhaar is blacklisted
    if is_aadhaar_blacklisted(aadhaar):
        reason = get_blacklist_reason(aadhaar)
        conn.close()
        
        # Add security alert notification
        add_notification(
            session['user_id'],
            'Security Alert',
            f'Blacklisted Aadhaar number detected: {mask_aadhaar(aadhaar)}. Reason: {reason}',
            'warning'
        )
        
        return jsonify({
            'success': False,
            'message': f'Entry denied. This Aadhaar number is blacklisted. Reason: {reason}',
            'status': 'blacklisted'
        }), 403
    
    # Find visitor with this Aadhaar
    cursor.execute("SELECT * FROM users WHERE aadhaar = ? AND role = 'visitor'", (aadhaar,))
    visitor = cursor.fetchone()
    
    if not visitor:
        conn.close()
        return jsonify({
            'success': False,
            'message': 'No visitor found with this Aadhaar number',
            'status': 'not_found'
        }), 404
    
    # Check if visitor has approved requests
    cursor.execute("""
    SELECT * FROM visit_requests 
    WHERE visitor_id = ? AND status = 'approved' AND date = ?
    """, (visitor['user_id'], datetime.now().strftime('%Y-%m-%d')))
    
    approved_requests = cursor.fetchall()
    
    # Process facial recognition if photo provided
    face_match_score = 0.5  # Default neutral score
    if photo_data and visitor['photo_file'] and FACE_RECOGNITION_AVAILABLE:
        # Get the path to the visitor's registration photo
        reg_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor['photo_file'])
        
        # Compare faces
        face_match_score = compare_faces(reg_photo_path, photo_data)
        
        # Save the entry photo
        entry_photo = handle_photo_upload(photo_data)
    else:
        entry_photo = None
    
    # Prepare response data
    visitor_data = {
        'name': visitor['name'],
        'user_id': visitor['user_id'],
        'masked_aadhaar': mask_aadhaar(visitor['aadhaar']),
        'photo_url': url_for('static', filename=f'uploads/{visitor["photo_file"]}') if visitor['photo_file'] else None,
        'face_match_score': face_match_score,
        'face_verified': face_match_score >= 0.5,  # Threshold for face verification
        'has_approved_visits': len(approved_requests) > 0,
        'approved_visits': [dict(req) for req in approved_requests]
    }
    
    conn.close()
    
    return jsonify({
        'success': True,
        'visitor': visitor_data,
        'status': 'verified'
    })

@app.route('/api/record_entry', methods=['POST'])
def record_entry():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    visitor_id = data.get('visitor_id')
    aadhaar = data.get('aadhaar')
    department = data.get('department')
    photo_data = data.get('photoData')
    face_match_score = data.get('faceMatchScore', 0.0)
    
    if not all([visitor_id, department]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get visitor information
    cursor.execute("SELECT name FROM users WHERE user_id = ?", (visitor_id,))
    visitor = cursor.fetchone()
    
    if not visitor:
        conn.close()
        return jsonify({'success': False, 'message': 'Visitor not found'}), 404
    
    # Generate pass ID
    pass_id = f"PASS-{datetime.now().year}-{str(uuid.uuid4())[:6].upper()}"
    
    # Save entry photo if provided
    entry_photo = handle_photo_upload(photo_data) if photo_data else None
    
    # Record entry
    cursor.execute('''
    INSERT INTO entry_logs (pass_id, visitor_name, visitor_id, department, aadhaar, entry_time, status, entry_photo, face_match_score)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        pass_id,
        visitor['name'],
        visitor_id,
        department,
        aadhaar,
        datetime.now().strftime('%H:%M:%S'),
        'inside',
        entry_photo,
        face_match_score
    ))
    
    conn.commit()
    conn.close()
    
    # Add notification for visitor
    add_notification(
        visitor_id,
        'Entry Recorded',
        f'Your entry to {department} was recorded at {datetime.now().strftime("%H:%M:%S")}.',
        'info'
    )
    
    return jsonify({
        'success': True,
        'message': 'Entry recorded successfully',
        'pass_id': pass_id
    })

@app.route('/api/record_exit', methods=['POST'])
def record_exit():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    pass_id = request.json.get('pass_id')
    
    if not pass_id:
        return jsonify({'success': False, 'message': 'Pass ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get entry log
    cursor.execute("SELECT * FROM entry_logs WHERE pass_id = ? AND status = 'inside'", (pass_id,))
    entry_log = cursor.fetchone()
    
    if not entry_log:
        conn.close()
        return jsonify({'success': False, 'message': 'No active entry found with this Pass ID'}), 404
    
    # Update entry log
    cursor.execute("UPDATE entry_logs SET exit_time = ?, status = 'exited' WHERE pass_id = ?", 
                  (datetime.now().strftime('%H:%M:%S'), pass_id))
    
    conn.commit()
    conn.close()
    
    # Add notification for visitor
    add_notification(
        entry_log['visitor_id'],
        'Exit Recorded',
        f'Your exit from {entry_log["department"]} was recorded at {datetime.now().strftime("%H:%M:%S")}.',
        'info'
    )
    
    return jsonify({
        'success': True,
        'message': 'Exit recorded successfully'
    })

# API routes for blacklist management
@app.route('/api/add_to_blacklist', methods=['POST'])
def add_to_blacklist():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    aadhaar = data.get('aadhaar')
    reason = data.get('reason', 'Security concern')
    
    if not aadhaar:
        return jsonify({'success': False, 'message': 'Aadhaar number is required'}), 400
    
    if not validate_aadhaar(aadhaar):
        return jsonify({'success': False, 'message': 'Invalid Aadhaar number format'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if already blacklisted
    cursor.execute("SELECT COUNT(*) FROM flagged_aadhaar WHERE aadhaar = ?", (aadhaar,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return jsonify({'success': False, 'message': 'This Aadhaar number is already blacklisted'}), 400
    
    # Add to blacklist
    cursor.execute('''
    INSERT INTO flagged_aadhaar (aadhaar, reason, added_by, added_on)
    VALUES (?, ?, ?, ?)
    ''', (
        aadhaar,
        reason,
        session['name'],
        datetime.now().strftime('%Y-%m-%d')
    ))
    
    # Check if any visitor has this Aadhaar
    cursor.execute("SELECT user_id FROM users WHERE aadhaar = ? AND role = 'visitor'", (aadhaar,))
    visitor = cursor.fetchone()
    
    if visitor:
        # Add notification for visitor
        add_notification(
            visitor['user_id'],
            'Account Restricted',
            'Your account has been restricted. Please contact the administrator for more information.',
            'error'
        )
    
    conn.commit()
    conn.close()
    
    # Add notification for security personnel
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE role = 'security'")
    security_personnel = cursor.fetchall()
    
    for person in security_personnel:
        add_notification(
            person['user_id'],
            'New Blacklisted Aadhaar',
            f'A new Aadhaar number has been added to the blacklist. Reason: {reason}',
            'warning'
        )
    
    return jsonify({
        'success': True,
        'message': 'Aadhaar number added to blacklist successfully'
    })

@app.route('/api/remove_from_blacklist', methods=['POST'])
def remove_from_blacklist():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    aadhaar = request.json.get('aadhaar')
    
    if not aadhaar:
        return jsonify({'success': False, 'message': 'Aadhaar number is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Remove from blacklist
    cursor.execute("DELETE FROM flagged_aadhaar WHERE aadhaar = ?", (aadhaar,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'success': False, 'message': 'Aadhaar number not found in blacklist'}), 404
    
    # Check if any visitor has this Aadhaar
    cursor.execute("SELECT user_id FROM users WHERE aadhaar = ? AND role = 'visitor'", (aadhaar,))
    visitor = cursor.fetchone()
    
    if visitor:
        # Add notification for visitor
        add_notification(
            visitor['user_id'],
            'Account Restored',
            'Your account restrictions have been lifted.',
            'success'
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Aadhaar number removed from blacklist successfully'
    })

# API routes for notifications
@app.route('/api/get_notifications')
def get_notifications():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    limit = request.args.get('limit', 10, type=int)
    
    notifications = get_user_notifications(session['user_id'], limit)
    
    return jsonify({
        'success': True,
        'notifications': [dict(notification) for notification in notifications],
        'unread_count': get_unread_notification_count(session['user_id'])
    })

@app.route('/api/mark_notification_read', methods=['POST'])
def mark_notification_read():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    notification_id = request.json.get('notification_id')
    
    if not notification_id:
        return jsonify({'success': False, 'message': 'Notification ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Mark notification as read
    cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", 
                  (notification_id, session['user_id']))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'success': False, 'message': 'Notification not found or not owned by user'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Notification marked as read'
    })

@app.route('/api/mark_all_notifications_read', methods=['POST'])
def mark_all_notifications_read():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Mark all notifications as read
    cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0", 
                  (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'All notifications marked as read'
    })

# API routes for user settings
@app.route('/api/get_settings')
def get_settings():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    settings = get_user_settings(session['user_id'])
    
    return jsonify({
        'success': True,
        'settings': settings
    })

@app.route('/api/update_settings', methods=['POST'])
def update_settings():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if settings exist
    cursor.execute("SELECT COUNT(*) FROM user_settings WHERE user_id = ?", (session['user_id'],))
    if cursor.fetchone()[0] == 0:
        # Create settings
        cursor.execute('''
        INSERT INTO user_settings (user_id, email_notifications, sms_notifications, theme, language, dashboard_widgets)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'],
            data.get('email_notifications', 1),
            data.get('sms_notifications', 0),
            data.get('theme', 'light'),
            data.get('language', 'en'),
            json.dumps(data.get('dashboard_widgets', []))
        ))
    else:
        # Update settings
        cursor.execute('''
        UPDATE user_settings 
        SET email_notifications = ?, sms_notifications = ?, theme = ?, language = ?, dashboard_widgets = ?
        WHERE user_id = ?
        ''', (
            data.get('email_notifications', 1),
            data.get('sms_notifications', 0),
            data.get('theme', 'light'),
            data.get('language', 'en'),
            json.dumps(data.get('dashboard_widgets', [])),
            session['user_id']
        ))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Settings updated successfully'
    })

# API route for generating visitor pass
@app.route('/api/generate_pass/<pass_id>')
def generate_pass(pass_id):
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get entry log
    cursor.execute("SELECT * FROM entry_logs WHERE pass_id = ?", (pass_id,))
    entry_log = cursor.fetchone()
    
    if not entry_log:
        conn.close()
        return jsonify({'success': False, 'message': 'Pass not found'}), 404
    
    # Get visitor information
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (entry_log['visitor_id'],))
    visitor = cursor.fetchone()
    
    conn.close()
    
    if not visitor:
        return jsonify({'success': False, 'message': 'Visitor not found'}), 404
    
    # Generate pass data
    pass_data = {
        'pass_id': entry_log['pass_id'],
        'visitor_name': visitor['name'],
        'visitor_id': visitor['user_id'],
        'department': entry_log['department'],
        'entry_time': entry_log['entry_time'],
        'date': datetime.now().strftime('%Y-%m-%d'),
        'photo_url': url_for('static', filename=f'uploads/{visitor["photo_file"]}') if visitor['photo_file'] else None,
        'masked_aadhaar': mask_aadhaar(visitor['aadhaar']) if visitor['aadhaar'] else "Not provided"
    }
    
    return jsonify({
        'success': True,
        'pass_data': pass_data
    })

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True)
