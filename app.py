from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, make_response
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
from PIL import Image, ImageDraw, ImageFont
import tempfile
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import csv

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
os.makedirs('static/notices', exist_ok=True)
os.makedirs('static/passes', exist_ok=True)

# Database setup with proper connection pooling and error handling
def get_db_connection():
    """Get database connection with proper configuration"""
    try:
        conn = sqlite3.connect(
            app.config['DATABASE'], 
            timeout=30.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=1000')
        conn.execute('PRAGMA temp_store=memory')
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def execute_db_query(query, params=None, fetch_one=False, fetch_all=False):
    """Execute database query with proper error handling"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            result = cursor.rowcount
            
        conn.commit()
        return result
        
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database query error: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()

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
        phone TEXT NOT NULL,
        email TEXT NOT NULL,
        aadhaar TEXT,
        photo_file TEXT,
        registration_date TEXT,
        status TEXT DEFAULT 'active',
        agency_code TEXT,
        agency_employee_id TEXT,
        agency_designation TEXT,
        last_login TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        join_request_status TEXT DEFAULT NULL
    )
    ''')
    
    # Create agencies table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS agencies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agency_code TEXT UNIQUE NOT NULL,
        agency_name TEXT NOT NULL,
        agency_type TEXT NOT NULL,
        contact_person TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        contact_phone TEXT NOT NULL,
        address TEXT NOT NULL,
        description TEXT,
        locations_access TEXT,
        registration_date TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_by TEXT,
        approved_by TEXT,
        approved_date TEXT,
        website TEXT,
        license_number TEXT,
        password TEXT
    )
    ''')
    
    # Create agency_employees table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS agency_employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agency_code TEXT NOT NULL,
        user_id TEXT NOT NULL,
        employee_id TEXT NOT NULL,
        designation TEXT NOT NULL,
        access_level TEXT DEFAULT 'basic',
        status TEXT DEFAULT 'active',
        added_date TEXT NOT NULL,
        added_by TEXT NOT NULL,
        FOREIGN KEY (agency_code) REFERENCES agencies (agency_code),
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )
    ''')
    
    # Create worker_passes table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS worker_passes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_id TEXT UNIQUE NOT NULL,
        agency_code TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        worker_name TEXT NOT NULL,
        pass_type TEXT NOT NULL,
        valid_from TEXT NOT NULL,
        valid_until TEXT NOT NULL,
        access_areas TEXT,
        purpose TEXT,
        status TEXT DEFAULT 'active',
        issued_by TEXT NOT NULL,
        issued_date TEXT NOT NULL,
        revoked_by TEXT,
        revoked_date TEXT,
        revoke_reason TEXT,
        qr_code TEXT,
        FOREIGN KEY (agency_code) REFERENCES agencies (agency_code),
        FOREIGN KEY (worker_id) REFERENCES users (user_id)
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
        submitted_on TEXT NOT NULL,
        agency_code TEXT,
        is_agency_visit INTEGER DEFAULT 0,
        approved_date TEXT,
        rejected_date TEXT
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
        aadhaar_last4 TEXT,
        entry_time TEXT NOT NULL,
        exit_time TEXT,
        status TEXT DEFAULT 'inside',
        entry_photo TEXT,
        face_match_score REAL,
        agency_code TEXT,
        pass_type TEXT DEFAULT 'visitor',
        security_officer TEXT,
        entry_date TEXT
    )
    ''')
    
    # Create flagged_aadhaar table (store only last 4 digits)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS flagged_aadhaar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        aadhaar_last4 TEXT NOT NULL,
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
        created_at TEXT NOT NULL,
        action_url TEXT,
        icon TEXT DEFAULT 'info-circle',
        priority TEXT DEFAULT 'normal'
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
        dashboard_widgets TEXT,
        notification_sound INTEGER DEFAULT 1,
        auto_logout INTEGER DEFAULT 30,
        profile_visibility TEXT DEFAULT 'private'
    )
    ''')
    
    # Create notices table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        type TEXT DEFAULT 'info',
        priority TEXT DEFAULT 'normal',
        target_audience TEXT DEFAULT 'all',
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        is_active INTEGER DEFAULT 1,
        attachment_file TEXT,
        views INTEGER DEFAULT 0
    )
    ''')
    
    # Create system_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT NOT NULL,
        level TEXT DEFAULT 'INFO'
    )
    ''')
    
    # Insert default users if they don't exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('visitor', 'password', 'visitor', 'Rahul Sharma', 'VIS-2024-001234', '+91 9876543210', 'rahul@example.com', '123456789012', 'placeholder.jpg', '2024-01-01', 'active', None, None, None),
            ('officer', 'password', 'officer', 'Dr. Rajesh Kumar', 'OFF-2024-001', '+91 9876543211', 'rajesh@example.com', None, 'placeholder.jpg', '2024-01-01', 'active', None, None, None),
            ('security', 'password', 'security', 'Suresh Gupta', 'SEC-001', '+91 9876543212', 'suresh@example.com', None, 'placeholder.jpg', '2024-01-01', 'active', None, None, None),
            ('admin', 'password', 'admin', 'System Administrator', 'ADMIN-001', '+91 9876543213', 'admin@example.com', None, 'placeholder.jpg', '2024-01-01', 'active', None, None, None),
            # Add some worker users for testing
        ]
        cursor.executemany('''
        INSERT INTO users (username, password, role, name, user_id, phone, email, aadhaar, photo_file, registration_date, status, agency_code, agency_employee_id, agency_designation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_users)
    
    # Insert default agencies if they don't exist
    cursor.execute("SELECT COUNT(*) FROM agencies")
    if cursor.fetchone()[0] == 0:
        default_agencies = [
            ('AGY001', 'TechCorp Solutions', 'IT Services', 'John Smith', 'john@techcorp.com', '+91 9876543215', '123 Tech Park, Bangalore', 'Leading IT solutions provider', json.dumps(['Building A', 'Building B', 'Conference Hall']), '2024-01-01', '2025-12-31', 'approved', 'ADMIN-001', 'ADMIN-001', '2024-01-01', 'www.techcorp.com', 'LIC123456', 'password'),
            ('AGY002', 'Global Consulting', 'Consulting', 'Sarah Johnson', 'sarah@globalconsult.com', '+91 9876543216', '456 Business District, Mumbai', 'Management consulting services', json.dumps(['Meeting Rooms', 'Executive Floor']), '2024-01-01', '2025-06-30', 'approved', 'ADMIN-001', 'ADMIN-001', '2024-01-01', 'www.globalconsult.com', 'LIC789012', 'password')
        ]
        cursor.executemany('''
        INSERT INTO agencies (agency_code, agency_name, agency_type, contact_person, contact_email, contact_phone, address, description, locations_access, registration_date, expiry_date, status, created_by, approved_by, approved_date, website, license_number, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_agencies)
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
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

def get_aadhaar_last4(aadhaar):
    """Get last 4 digits of Aadhaar number"""
    if not aadhaar:
        return None
    aadhaar = aadhaar.replace(' ', '').replace('-', '')
    return aadhaar[-4:] if len(aadhaar) >= 4 else None

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
    """Check if Aadhaar number is blacklisted using last 4 digits"""
    last4 = get_aadhaar_last4(aadhaar)
    if not last4:
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM flagged_aadhaar WHERE aadhaar_last4 = ?", (last4,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def get_blacklist_reason(aadhaar):
    """Get the reason why an Aadhaar number is blacklisted"""
    last4 = get_aadhaar_last4(aadhaar)
    if not last4:
        return "Unknown reason"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT reason FROM flagged_aadhaar WHERE aadhaar_last4 = ?", (last4,))
    result = cursor.fetchone()
    conn.close()
    return result['reason'] if result else "Unknown reason"

def log_system_action(user_id, action, details=None, level='INFO'):
    """Log system actions"""
    try:
        execute_db_query('''
        INSERT INTO system_logs (user_id, action, details, timestamp, level)
        VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, details, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), level))
    except Exception as e:
        logger.error(f"Failed to log system action: {str(e)}")

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

def get_user_notifications(user_id, limit=10):
    """Get notifications for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM notifications 
    WHERE user_id = ? 
    ORDER BY priority DESC, created_at DESC, is_read ASC
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

def add_notification(user_id, title, message, notification_type='info', action_url=None, icon='info-circle', priority='normal'):
    """Add a notification for a user"""
    try:
        execute_db_query("""
        INSERT INTO notifications (user_id, title, message, type, created_at, action_url, icon, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, title, message, notification_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), action_url, icon, priority))
    except Exception as e:
        logger.error(f"Failed to add notification: {str(e)}")

def send_notification_to_role(role, title, message, notification_type='info', action_url=None, icon='info-circle', priority='normal'):
    """Send notification to all users of a specific role"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE role = ? AND status = 'active'", (role,))
    users = cursor.fetchall()
    
    for user in users:
        add_notification(user['user_id'], title, message, notification_type, action_url, icon, priority)
    
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
        'dashboard_widgets': [],
        'notification_sound': 1,
        'auto_logout': 30,
        'profile_visibility': 'private'
    }

def get_agency_by_code(agency_code):
    """Get agency details by code"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agencies WHERE agency_code = ?", (agency_code,))
    agency = cursor.fetchone()
    conn.close()
    return agency

def is_agency_employee(user_id, agency_code):
    """Check if user is an employee of the agency"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM agency_employees WHERE user_id = ? AND agency_code = ? AND status = 'active'", (user_id, agency_code))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def generate_agency_code():
    """Generate unique agency code"""
    while True:
        code = f"AGY{str(uuid.uuid4())[:6].upper()}"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM agencies WHERE agency_code = ?", (code,))
        if cursor.fetchone()[0] == 0:
            conn.close()
            return code
        conn.close()

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
    elif role == 'agency':
        return f"AGY-{year}-{random_id[:4]}"
    else:
        return f"USER-{random_id}"

def generate_pass_pdf(pass_data):
    """Generate PDF pass for worker"""
    try:
        # Create filename
        filename = f"pass_{pass_data['pass_id']}.pdf"
        filepath = os.path.join('static/passes', filename)
        
        # Create PDF
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("WORKER ACCESS PASS", title_style))
        story.append(Spacer(1, 20))
        
        # Pass details table
        data = [
            ['Pass ID:', pass_data['pass_id']],
            ['Worker Name:', pass_data['worker_name']],
            ['Worker ID:', pass_data['worker_id']],
            ['Agency:', pass_data.get('agency_name', 'N/A')],
            ['Pass Type:', pass_data['pass_type'].title()],
            ['Valid From:', pass_data['valid_from']],
            ['Valid Until:', pass_data['valid_until']],
            ['Status:', pass_data['status'].title()],
            ['Issued Date:', pass_data['issued_date']],
        ]
        
        table = Table(data, colWidths=[2*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 30))
        
        # Access areas
        if pass_data.get('access_areas'):
            story.append(Paragraph("Authorized Access Areas:", styles['Heading2']))
            for area in pass_data['access_areas']:
                story.append(Paragraph(f"• {area}", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Purpose
        if pass_data.get('purpose'):
            story.append(Paragraph("Purpose:", styles['Heading2']))
            story.append(Paragraph(pass_data['purpose'], styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=10,
            alignment=1,
            textColor=colors.grey
        )
        story.append(Spacer(1, 50))
        story.append(Paragraph("This pass is valid only for the specified dates and areas.", footer_style))
        story.append(Paragraph("Pass4Port Visitor Management System", footer_style))
        
        # Build PDF
        doc.build(story)
        
        return filename
        
    except Exception as e:
        logger.error(f"Error generating pass PDF: {str(e)}")
        return None

# Routes
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/verify_face', methods=['POST'])
def api_verify_face():
    data = request.get_json()
    visitor_id = data.get('visitor_id')
    photo_data = data.get('photo_data')

    if not visitor_id or not photo_data:
        return jsonify({'success': False, 'message': 'Missing data'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT photo_file FROM users WHERE user_id = ?", (visitor_id,))
    user = cursor.fetchone()
    conn.close()

    if not user or not user['photo_file']:
        return jsonify({'success': False, 'message': 'No photo on file'}), 404

    known_image_path = os.path.join(app.config['UPLOAD_FOLDER'], user['photo_file'])

    match_score = compare_faces(known_image_path, photo_data)

    if match_score >= 0.75:
        return jsonify({'success': True, 'match_score': match_score})
    else:
        return jsonify({'success': False, 'match_score': match_score, 'message': 'Face does not match'})


@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')
    user_type = request.form.get('userType')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_type == 'agency':
        # For agencies, username is agency_code
        cursor.execute("SELECT * FROM agencies WHERE agency_code = ?", (username,))
        agency = cursor.fetchone()
        
        if agency and agency['password'] == password and agency['status'] == 'approved':
            # Find agency admin user
            cursor.execute("SELECT * FROM users WHERE agency_code = ? AND role = 'agency' LIMIT 1", (username,))
            user = cursor.fetchone()
            
            if user:
                session['user'] = user['username']
                session['role'] = 'agency'
                session['name'] = agency['agency_name']
                session['user_id'] = user['user_id']
                session['agency_code'] = username
                
                # Update last login
                cursor.execute("UPDATE users SET last_login = ? WHERE user_id = ?", 
                             (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['user_id']))
                conn.commit()
                
                # Log system action
                log_system_action(user['user_id'], 'LOGIN', f'Agency logged in: {agency["agency_name"]}')
                
                conn.close()
                return redirect(url_for('dashboard_agency'))
        
        conn.close()
        flash('Invalid agency credentials or agency not approved', 'error')
        return redirect(url_for('login'))
    else:
        # Regular user login
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # In production, use: if check_password(user['password'], password)
            if user['password'] == password and user['role'] == user_type:
                if user['status'] == 'pending':
                    conn.close()
                    flash('Your account is pending approval. Please wait for admin approval.', 'info')
                    return redirect(url_for('login'))
                
                # Update last login
                cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", 
                             (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
                conn.commit()
                
                session['user'] = username
                session['role'] = user_type
                session['name'] = user['name']
                session['user_id'] = user['user_id']
                session['agency_code'] = user['agency_code']
                
                # Log system action
                log_system_action(user['user_id'], 'LOGIN', f'User logged in as {user_type}')
                
                # Add login notification
                add_notification(
                    user['user_id'],
                    'Login Successful',
                    f'You logged in at {datetime.now().strftime("%H:%M:%S")} on {datetime.now().strftime("%Y-%m-%d")}',
                    'info',
                    None,
                    'sign-in-alt'
                )
                
                conn.close()
                return redirect(url_for(f'dashboard_{user_type}'))
        
        conn.close()
        flash('Invalid credentials or user type mismatch', 'error')
        return redirect(url_for('login'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def handle_register():
    try:
        logger.debug("Registration request received")
        
        # Get all form data
        full_name = request.form.get('fullName', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        aadhaar = request.form.get('aadhaar', '').strip()
        agency_id = request.form.get('agencyId', '').strip()
        
        # Prevent admin registration
        if role == 'admin':
            return jsonify({
                'success': False,
                'message': 'Admin accounts cannot be created through registration. Contact existing admin for access.'
            }), 400
        
        # Validate required fields
        if not all([full_name, phone, email, username, password, role]):
            missing_fields = []
            if not full_name: missing_fields.append('Full Name')
            if not phone: missing_fields.append('Phone')
            if not email: missing_fields.append('Email')
            if not username: missing_fields.append('Username')
            if not password: missing_fields.append('Password')
            if not role: missing_fields.append('Role')
            
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Check if username exists
        existing_user = execute_db_query(
            "SELECT COUNT(*) FROM users WHERE username = ?", 
            (username,), 
            fetch_one=True
        )
        
        if existing_user[0] > 0:
            return jsonify({
                'success': False,
                'message': 'Username already exists'
            }), 400
        
        # Validate agency ID if provided
        agency_code = None
        join_request_status = None
        if agency_id:
            agency = execute_db_query(
                "SELECT * FROM agencies WHERE agency_code = ? AND status = 'approved'", 
                (agency_id,), 
                fetch_one=True
            )
            if not agency:
                return jsonify({
                    'success': False,
                    'message': 'Invalid or unapproved agency ID'
                }), 400
            agency_code = agency_id
            join_request_status = 'pending'
        
        # Validate Aadhaar number for visitors
        if role == 'visitor':
            if not aadhaar:
                return jsonify({
                    'success': False,
                    'message': 'Aadhaar number is required for visitors'
                }), 400
                
            if not validate_aadhaar(aadhaar):
                return jsonify({
                    'success': False,
                    'message': 'Please enter a valid 12-digit Aadhaar number'
                }), 400
            
            # Check if Aadhaar is blacklisted
            if is_aadhaar_blacklisted(aadhaar):
                reason = get_blacklist_reason(aadhaar)
                return jsonify({
                    'success': False,
                    'message': f'Registration not allowed. Reason: {reason}. Please contact the administrator.'
                }), 400
        
        # Handle photo upload
        photo_file = handle_photo_upload(request.form.get('photoData'))
        
        if not photo_file:
            photo_file = "placeholder.jpg"
        
        # Generate user ID
        user_id = generate_user_id(role)
        
        # Process registration based on role - all non-visitors need admin approval
        status = 'active' if role == 'visitor' else 'pending'
        
        # Insert user into database
        execute_db_query('''
        INSERT INTO users (username, password, role, name, user_id, phone, email, aadhaar, photo_file, registration_date, status, agency_code, created_at, join_request_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            status,
            agency_code,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            join_request_status
        ))
        
        # Create default user settings
        execute_db_query('''
        INSERT INTO user_settings (user_id, email_notifications, sms_notifications, theme, language, dashboard_widgets, notification_sound, auto_logout, profile_visibility)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            1,
            0,
            'light',
            'en',
            json.dumps(['profile', 'notifications']),
            1,
            30,
            'private'
        ))
        
        # Log system action
        log_system_action(user_id, 'REGISTER', f'New {role} registration')
        
        # Add notification for admin about new registration
        if status == 'pending':
            add_notification(
                'ADMIN-001',
                'New Registration',
                f'New {role} registration: {full_name} ({user_id}) requires approval',
                'info',
                '/dashboard/admin',
                'user-plus',
                'high'
            )
        
        # Add notification for agency if joining
        if agency_code and join_request_status == 'pending':
            # Find agency admin
            agency_admin = execute_db_query(
                "SELECT user_id FROM users WHERE agency_code = ? AND role = 'agency' LIMIT 1",
                (agency_code,),
                fetch_one=True
            )
            if agency_admin:
                add_notification(
                    agency_admin['user_id'],
                    'New Join Request',
                    f'New worker join request: {full_name} ({user_id}) wants to join your agency',
                    'info',
                    '/dashboard/agency',
                    'user-plus',
                    'high'
                )
        
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

@app.route('/register_agency')
def register_agency():
    return render_template('register_agency.html')

@app.route('/register_agency', methods=['POST'])
def handle_register_agency():
    try:
        # Get form data
        agency_name = request.form.get('agencyName', '').strip()
        agency_type = request.form.get('agencyType', '').strip()
        contact_person = request.form.get('contactPerson', '').strip()
        contact_email = request.form.get('contactEmail', '').strip()
        contact_phone = request.form.get('contactPhone', '').strip()
        address = request.form.get('address', '').strip()
        description = request.form.get('description', '').strip()
        locations_access = request.form.getlist('locationsAccess')
        expiry_date = request.form.get('expiryDate', '').strip()
        website = request.form.get('website', '').strip()
        license_number = request.form.get('licenseNumber', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate required fields
        if not all([agency_name, agency_type, contact_person, contact_email, contact_phone, address, expiry_date, password]):
            return jsonify({
                'success': False,
                'message': 'All required fields must be filled'
            }), 400
        
        # Validate expiry date
        try:
            expiry_datetime = datetime.strptime(expiry_date, '%Y-%m-%d')
            if expiry_datetime <= datetime.now():
                return jsonify({
                    'success': False,
                    'message': 'Expiry date must be in the future'
                }), 400
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid expiry date format'
            }), 400
        
        # Generate agency code
        agency_code = generate_agency_code()
        
        # Insert agency into database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO agencies (agency_code, agency_name, agency_type, contact_person, contact_email, contact_phone, address, description, locations_access, registration_date, expiry_date, status, created_by, website, license_number, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agency_code,
            agency_name,
            agency_type,
            contact_person,
            contact_email,
            contact_phone,
            address,
            description,
            json.dumps(locations_access),
            datetime.now().strftime('%Y-%m-%d'),
            expiry_date,
            'pending',
            'SYSTEM',
            website,
            license_number,
            password
        ))
        
        conn.commit()
        conn.close()
        
        # Log system action
        log_system_action(None, 'AGENCY_REGISTER', f'New agency registration: {agency_name}')
        
        # Add notification for admin
        add_notification(
            'ADMIN-001',
            'New Agency Registration',
            f'New agency registration: {agency_name} ({agency_code}) requires approval',
            'info',
            '/dashboard/admin',
            'building',
            'high'
        )
        
        return jsonify({
            'success': True,
            'message': f'Agency registration submitted successfully. Your Agency ID is: {agency_code}. You will be notified once approved.',
            'agency_code': agency_code
        })
        
    except Exception as e:
        logger.error(f"Agency registration error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Registration failed: {str(e)}'
        }), 500

# Dashboard routes
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
    
    # Get active notices
    cursor.execute("SELECT * FROM notices WHERE is_active = 1 AND (target_audience = 'all' OR target_audience = 'visitor') AND (expires_at IS NULL OR expires_at > ?) ORDER BY priority DESC, created_at DESC", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),))
    notices = cursor.fetchall()
    
    conn.close()
    
    masked_aadhaar = mask_aadhaar(user['aadhaar']) if user else "Not provided"
    
    return render_template('dashboard_visitor.html', 
                          requests=requests,
                          masked_aadhaar=masked_aadhaar,
                          notifications=notifications,
                          unread_count=unread_count,
                          settings=settings,
                          notices=notices,
                          user=user)

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
    
    # Get active notices
    cursor.execute("SELECT * FROM notices WHERE is_active = 1 AND (target_audience = 'all' OR target_audience = 'officer') AND (expires_at IS NULL OR expires_at > ?) ORDER BY priority DESC, created_at DESC", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),))
    notices = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard_officer.html', 
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings,
                         notices=notices,
                         now=datetime.now)

@app.route('/dashboard/security')
def dashboard_security():
    if 'user' not in session or session['role'] != 'security':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get entry logs
    cursor.execute("SELECT * FROM entry_logs ORDER BY entry_time DESC LIMIT 50")
    entry_logs = cursor.fetchall()
    
    # Get active passes for verification - improved query with better date handling
    today = datetime.now().strftime('%Y-%m-%d')

    # First, get all visitor passes (approved visit requests for today)
    cursor.execute("""
    SELECT 
        vr.request_id as pass_id,
        vr.visitor_id as worker_id,
        vr.visitor_name as worker_name,
        'visitor' as pass_type,
        vr.department as access_areas,
        NULL as agency_code,
        vr.date as valid_from,
        vr.date as valid_until,
        u.photo_file,
        NULL as agency_name
    FROM visit_requests vr
    JOIN users u ON vr.visitor_id = u.user_id
    WHERE vr.status = 'approved' 
    AND vr.date = ?
    UNION ALL
    SELECT 
        wp.pass_id, 
        wp.worker_id, 
        wp.worker_name, 
        wp.pass_type, 
        wp.access_areas,
        wp.agency_code,
        wp.valid_from,
        wp.valid_until,
        u.photo_file,
        a.agency_name
    FROM worker_passes wp
    JOIN users u ON wp.worker_id = u.user_id
    LEFT JOIN agencies a ON wp.agency_code = a.agency_code
    WHERE wp.status = 'active' 
    AND wp.valid_from <= ? 
    AND wp.valid_until >= ?
    ORDER BY worker_name
    """, (today, today, today))

    active_passes_raw = cursor.fetchall()

    # Convert to list of dictionaries and parse access_areas
    active_passes = []
    for pass_row in active_passes_raw:
        pass_dict = dict(pass_row)
        try:
            # Handle access_areas - for visitors it's department, for workers it's JSON
            if pass_dict['pass_type'] == 'visitor':
                # For visitors, access_areas contains the department name
                pass_dict['access_areas'] = [pass_dict['access_areas']] if pass_dict['access_areas'] else []
            else:
                # For workers, parse JSON access_areas
                if pass_dict['access_areas']:
                    pass_dict['access_areas'] = json.loads(pass_dict['access_areas'])
                else:
                    pass_dict['access_areas'] = []
        except (json.JSONDecodeError, TypeError):
            pass_dict['access_areas'] = []
    
        # Add pass type indicator for display
        if pass_dict['pass_type'] == 'visitor':
            pass_dict['pass_type_display'] = 'Visitor Pass'
        else:
            pass_dict['pass_type_display'] = f"{pass_dict['pass_type'].title()} Worker Pass"
    
        active_passes.append(pass_dict)

    # Debug logging
    logger.debug(f"Found {len(active_passes)} active passes for date {today}")
    for pass_item in active_passes:
        logger.debug(f"Pass: {pass_item['pass_id']} - {pass_item['worker_name']} - Type: {pass_item['pass_type']} - Valid: {pass_item['valid_from']} to {pass_item['valid_until']}")
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    # Get active notices
    cursor.execute("""
    SELECT * FROM notices 
    WHERE is_active = 1 
    AND (target_audience = 'all' OR target_audience = 'security') 
    AND (expires_at IS NULL OR expires_at > ?) 
    ORDER BY priority DESC, created_at DESC
    """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),))
    notices = cursor.fetchall()
    
    conn.close()
    
    # Add masked Aadhaar to entry logs for display
    entry_logs_with_masked = []
    for log in entry_logs:
        log_dict = dict(log)
        if log['aadhaar_last4']:
            log_dict['masked_aadhaar'] = f"XXXX-XXXX-{log['aadhaar_last4']}"
        else:
            log_dict['masked_aadhaar'] = "Not provided"
        entry_logs_with_masked.append(log_dict)
    
    return render_template('dashboard_security.html', 
                         entry_logs=entry_logs_with_masked,
                         active_passes=active_passes,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings,
                         notices=notices)

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
    
    cursor.execute("SELECT COUNT(*) FROM agencies WHERE status = 'pending'")
    pending_agencies = cursor.fetchone()[0]
    
    # Get pending registrations
    cursor.execute("SELECT * FROM users WHERE status = 'pending'")
    pending_registrations = cursor.fetchall()
    
    # Get pending agencies with full details
    cursor.execute("SELECT * FROM agencies WHERE status = 'pending'")
    pending_agency_registrations = cursor.fetchall()
    
    # Get approved agencies
    cursor.execute("SELECT * FROM agencies WHERE status = 'approved'")
    approved_agencies = cursor.fetchall()
    
    # Get users by role for admin tabs
    cursor.execute("SELECT * FROM users WHERE role = 'visitor' AND status = 'active'")
    visitors = cursor.fetchall()
    
    cursor.execute("SELECT * FROM users WHERE role = 'officer' AND status = 'active'")
    officers = cursor.fetchall()
    
    cursor.execute("SELECT * FROM users WHERE role = 'security' AND status = 'active'")
    security_personnel = cursor.fetchall()
    
    # Parse locations_access for agencies
    agencies_with_parsed_locations = []
    for agency in pending_agency_registrations:
        agency_dict = dict(agency)
        try:
            agency_dict['locations_access_list'] = json.loads(agency['locations_access']) if agency['locations_access'] else []
        except:
            agency_dict['locations_access_list'] = []
        agencies_with_parsed_locations.append(agency_dict)
    
    # Get flagged Aadhaar numbers
    cursor.execute("SELECT * FROM flagged_aadhaar ORDER BY added_on DESC")
    flagged_aadhaar = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    # Get active notices
    cursor.execute("SELECT * FROM notices WHERE is_active = 1 ORDER BY priority DESC, created_at DESC")
    notices = cursor.fetchall()
    
    # Get system alerts (placeholder)
    system_alerts = []
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'active_visitors': active_visitors,
        'pending_approvals': pending_approvals,
        'flagged_ids': flagged_ids,
        'pending_agencies': pending_agencies
    }
    
    return render_template('dashboard_admin.html', 
                         stats=stats, 
                         flagged_aadhaar=flagged_aadhaar,
                         pending_registrations=pending_registrations,
                         pending_agency_registrations=agencies_with_parsed_locations,
                         approved_agencies=approved_agencies,
                         visitors=visitors,
                         officers=officers,
                         security_personnel=security_personnel,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings,
                         notices=notices,
                         system_alerts=system_alerts)

@app.route('/dashboard/agency')
def dashboard_agency():
    if 'user' not in session or session['role'] != 'agency':
        return redirect(url_for('login'))
    
    agency_code = session.get('agency_code')
    if not agency_code:
        flash('No agency associated with your account', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get agency details
    cursor.execute("SELECT * FROM agencies WHERE agency_code = ?", (agency_code,))
    agency = cursor.fetchone()
    
    if agency:
        agency_dict = dict(agency)
        try:
            agency_dict['locations_access'] = json.loads(agency['locations_access']) if agency['locations_access'] else []
        except:
            agency_dict['locations_access'] = []
        agency = agency_dict
    
    # Get join requests (users who want to join this agency)
    cursor.execute("""
    SELECT * FROM users 
    WHERE agency_code = ? AND join_request_status = 'pending' 
    ORDER BY created_at DESC
    """, (agency_code,))
    join_requests = cursor.fetchall()
    
    # Get active workers
    cursor.execute("""
    SELECT * FROM users 
    WHERE agency_code = ? AND join_request_status = 'approved' AND status = 'active'
    ORDER BY name
    """, (agency_code,))
    active_workers = cursor.fetchall()
    
    # Get active passes
    cursor.execute("""
    SELECT wp.*, u.name as worker_name, u.photo_file 
    FROM worker_passes wp 
    JOIN users u ON wp.worker_id = u.user_id 
    WHERE wp.agency_code = ? AND wp.status = 'active'
    ORDER BY wp.issued_date DESC
    """, (agency_code,))
    active_passes = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    # Get recent activities (simplified)
    recent_activities = [
        {'icon': 'user-plus', 'description': f'{len(join_requests)} pending join requests', 'timestamp': 'Today'},
        {'icon': 'id-card', 'description': f'{len(active_passes)} active passes issued', 'timestamp': 'This week'},
    ]
    
    conn.close()
    
    # Statistics
    stats = {
        'total_workers': len(active_workers) + len(join_requests),
        'active_workers': len(active_workers),
        'pending_requests': len(join_requests),
        'active_passes': len([p for p in active_passes if p['status'] == 'active']),
        'revoked_passes': len([p for p in active_passes if p['status'] == 'revoked'])
    }
    
    return render_template('dashboard_agency.html',
                         agency=agency,
                         join_requests=join_requests,
                         active_workers=active_workers,
                         active_passes=active_passes,
                         stats=stats,
                         notifications=notifications,
                         unread_count=unread_count,
                         settings=settings,
                         recent_activities=recent_activities)

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user data
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    conn.close()
    
    # Mask Aadhaar for display
    user_dict = dict(user)
    if user_dict.get('aadhaar'):
        user_dict['masked_aadhaar'] = mask_aadhaar(user_dict['aadhaar'])
    else:
        user_dict['masked_aadhaar'] = "Not provided"
    
    return render_template('profile.html', 
                         user=user_dict,
                         settings=settings,
                         notifications=notifications,
                         unread_count=unread_count)

@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get user settings
    settings = get_user_settings(session['user_id'])
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    return render_template('settings.html', 
                         settings=settings,
                         notifications=notifications,
                         unread_count=unread_count)

@app.route('/help')
def help():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    return render_template('help.html',
                         notifications=notifications,
                         unread_count=unread_count)

@app.route('/agencies')
def agencies():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get approved agencies
    cursor.execute("SELECT * FROM agencies WHERE status = 'approved' ORDER BY agency_name")
    agencies = cursor.fetchall()
    
    # Get user notifications
    notifications = get_user_notifications(session['user_id'])
    unread_count = get_unread_notification_count(session['user_id'])
    
    conn.close()
    
    return render_template('agencies.html',
                         agencies=agencies,
                         notifications=notifications,
                         unread_count=unread_count)

# API routes for profile and settings
@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.json
            photo_data = data.get('photoData')
        else:
            data = request.form.to_dict()
            photo_data = request.form.get('photoData')
        
        # Get current user data
        user = execute_db_query(
            "SELECT * FROM users WHERE user_id = ?",
            (session['user_id'],),
            fetch_one=True
        )
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Update allowed fields
        update_fields = []
        update_values = []
        
        if 'name' in data and data['name'].strip():
            update_fields.append('name = ?')
            update_values.append(data['name'].strip())
        
        if 'phone' in data and data['phone'].strip():
            update_fields.append('phone = ?')
            update_values.append(data['phone'].strip())
        
        if 'email' in data and data['email'].strip():
            update_fields.append('email = ?')
            update_values.append(data['email'].strip())
        
        # Handle photo upload
        if photo_data:
            photo_file = handle_photo_upload(photo_data)
            if photo_file:
                update_fields.append('photo_file = ?')
                update_values.append(photo_file)
        
        # Handle password change
        if 'current_password' in data and 'new_password' in data:
            current_password = data['current_password']
            new_password = data['new_password']
            
            if current_password and new_password:
                # Verify current password (in production, use check_password)
                if user['password'] == current_password:
                    update_fields.append('password = ?')
                    update_values.append(new_password)  # In production, use hash_password
                else:
                    return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
        
        if update_fields:
            update_values.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE user_id = ?"
            execute_db_query(query, tuple(update_values))
            
            # Log system action
            log_system_action(session['user_id'], 'UPDATE_PROFILE', 'Profile updated')
            
            # Add notification
            add_notification(
                session['user_id'],
                'Profile Updated',
                'Your profile information has been updated successfully.',
                'success',
                None,
                'user-edit'
            )
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to update profile'
        }), 500

@app.route('/api/update_settings', methods=['POST'])
def update_settings():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        
        # Convert dashboard_widgets list to JSON string
        dashboard_widgets = data.get('dashboard_widgets', [])
        if isinstance(dashboard_widgets, list):
            dashboard_widgets_json = json.dumps(dashboard_widgets)
        else:
            dashboard_widgets_json = json.dumps([])
        
        # Update user settings
        execute_db_query('''
        INSERT OR REPLACE INTO user_settings 
        (user_id, email_notifications, sms_notifications, theme, language, dashboard_widgets, notification_sound, auto_logout, profile_visibility)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'],
            data.get('email_notifications', 1),
            data.get('sms_notifications', 0),
            data.get('theme', 'light'),
            data.get('language', 'en'),
            dashboard_widgets_json,
            data.get('notification_sound', 1),
            data.get('auto_logout', 30),
            data.get('profile_visibility', 'private')
        ))
        
        # Log system action
        log_system_action(session['user_id'], 'UPDATE_SETTINGS', 'Settings updated')
        
        return jsonify({
            'success': True,
            'message': 'Settings updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to update settings'
        }), 500

# API routes for admin functions
@app.route('/api/send_notification', methods=['POST'])
def send_notification():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        title = data.get('title')
        message = data.get('message')
        target_audience = data.get('target_audience', 'all')
        notification_type = data.get('type', 'info')
        priority = data.get('priority', 'normal')
        
        if not title or not message:
            return jsonify({'success': False, 'message': 'Title and message are required'}), 400
        
        # Send notification based on target audience
        if target_audience == 'all':
            # Send to all active users
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE status = 'active'")
            users = cursor.fetchall()
            conn.close()
            
            for user in users:
                add_notification(user['user_id'], title, message, notification_type, None, 'bullhorn', priority)
        else:
            # Send to specific role
            send_notification_to_role(target_audience, title, message, notification_type, None, 'bullhorn', priority)
        
        # Log system action
        log_system_action(session['user_id'], 'SEND_NOTIFICATION', f'Sent notification to {target_audience}: {title}')
        
        return jsonify({
            'success': True,
            'message': 'Notification sent successfully'
        })
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to send notification'
        }), 500

@app.route('/api/get_user_details')
def get_user_details():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    username = request.args.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    try:
        user = execute_db_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        user_dict = dict(user)
        if user_dict.get('aadhaar'):
            user_dict['masked_aadhaar'] = mask_aadhaar(user_dict['aadhaar'])
        
        # Generate HTML content for modal
        html_content = f"""
        <div class="space-y-4">
            <div class="flex items-center space-x-4">
                <img src="/static/uploads/{user_dict['photo_file']}" alt="Profile" class="w-16 h-16 rounded-full object-cover">
                <div>
                    <h4 class="font-medium text-gray-900">{user_dict['name']}</h4>
                    <p class="text-sm text-gray-500">{user_dict['user_id']}</p>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-4 text-sm">
                <div><strong>Email:</strong> {user_dict['email']}</div>
                <div><strong>Phone:</strong> {user_dict['phone']}</div>
                <div><strong>Role:</strong> {user_dict['role'].title()}</div>
                <div><strong>Status:</strong> {user_dict['status'].title()}</div>
                <div><strong>Registered:</strong> {user_dict['registration_date']}</div>
                <div><strong>Last Login:</strong> {user_dict['last_login'] or 'Never'}</div>
            </div>
            {f'<div class="text-sm"><strong>Aadhaar:</strong> {user_dict["masked_aadhaar"]}</div>' if user_dict.get('aadhaar') else ''}
        </div>
        """
        
        return jsonify({
            'success': True,
            'html': html_content
        })
        
    except Exception as e:
        logger.error(f"Error getting user details: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get user details'
        }), 500

@app.route('/api/get_agency_details')
def get_agency_details():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    agency_code = request.args.get('agency_code')
    if not agency_code:
        return jsonify({'success': False, 'message': 'Agency code is required'}), 400
    
    try:
        agency = execute_db_query(
            "SELECT * FROM agencies WHERE agency_code = ?",
            (agency_code,),
            fetch_one=True
        )
        
        if not agency:
            return jsonify({'success': False, 'message': 'Agency not found'}), 404
        
        agency_dict = dict(agency)
        try:
            locations_access = json.loads(agency_dict['locations_access']) if agency_dict['locations_access'] else []
        except:
            locations_access = []
        
        # Generate HTML content for modal
        html_content = f"""
        <div class="space-y-4">
            <div>
                <h4 class="font-medium text-gray-900">{agency_dict['agency_name']}</h4>
                <p class="text-sm text-gray-500">{agency_dict['agency_code']} - {agency_dict['agency_type']}</p>
            </div>
            <div class="grid grid-cols-1 gap-4 text-sm">
                <div><strong>Contact Person:</strong> {agency_dict['contact_person']}</div>
                <div><strong>Email:</strong> {agency_dict['contact_email']}</div>
                <div><strong>Phone:</strong> {agency_dict['contact_phone']}</div>
                <div><strong>Address:</strong> {agency_dict['address']}</div>
                <div><strong>Website:</strong> {agency_dict['website'] or 'Not provided'}</div>
                <div><strong>License:</strong> {agency_dict['license_number'] or 'Not provided'}</div>
                <div><strong>Registered:</strong> {agency_dict['registration_date']}</div>
                <div><strong>Expires:</strong> {agency_dict['expiry_date']}</div>
                <div><strong>Status:</strong> {agency_dict['status'].title()}</div>
            </div>
            <div class="text-sm">
                <strong>Description:</strong>
                <p class="mt-1 text-gray-600">{agency_dict['description'] or 'No description provided'}</p>
            </div>
            <div class="text-sm">
                <strong>Access Locations:</strong>
                <ul class="mt-1 list-disc list-inside text-gray-600">
                    {''.join([f'<li>{location}</li>' for location in locations_access]) if locations_access else '<li>No locations specified</li>'}
                </ul>
            </div>
        </div>
        """
        
        return jsonify({
            'success': True,
            'html': html_content
        })
        
    except Exception as e:
        logger.error(f"Error getting agency details: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get agency details'
        }), 500

@app.route('/api/activate_user', methods=['POST'])
def activate_user():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        username = data.get('username')
        
        if not username:
            return jsonify({'success': False, 'message': 'Username is required'}), 400
        
        execute_db_query(
            "UPDATE users SET status = 'active' WHERE username = ?",
            (username,)
        )
        
        # Get user details for notification
        user = execute_db_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )
        
        if user:
            add_notification(
                user['user_id'],
                'Account Activated',
                'Your account has been activated by the administrator.',
                'success',
                None,
                'user-check'
            )
        
        log_system_action(session['user_id'], 'ACTIVATE_USER', f'Activated user: {username}')
        
        return jsonify({
            'success': True,
            'message': 'User activated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error activating user: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to activate user'
        }), 500

@app.route('/api/deactivate_user', methods=['POST'])
def deactivate_user():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        username = data.get('username')
        
        if not username:
            return jsonify({'success': False, 'message': 'Username is required'}), 400
        
        execute_db_query(
            "UPDATE users SET status = 'inactive' WHERE username = ?",
            (username,)
        )
        
        # Get user details for notification
        user = execute_db_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )
        
        if user:
            add_notification(
                user['user_id'],
                'Account Deactivated',
                'Your account has been deactivated by the administrator.',
                'warning',
                None,
                'user-slash'
            )
        
        log_system_action(session['user_id'], 'DEACTIVATE_USER', f'Deactivated user: {username}')
        
        return jsonify({
            'success': True,
            'message': 'User deactivated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deactivating user: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to deactivate user'
        }), 500

@app.route('/api/export_visitors')
def export_visitors():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Get all visitors
        visitors = execute_db_query(
            "SELECT * FROM users WHERE role = 'visitor'",
            fetch_all=True
        )
        
        # Create CSV content
        output = BytesIO()
        output.write('\ufeff'.encode('utf8'))  # BOM for Excel
        
        fieldnames = ['name', 'user_id', 'email', 'phone', 'registration_date', 'status', 'last_login']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        
        writer.writeheader()
        for visitor in visitors:
            visitor_dict = dict(visitor)
            # Remove sensitive data
            visitor_dict.pop('aadhaar', None)
            visitor_dict.pop('password', None)
            writer.writerow(visitor_dict)
        
        output.seek(0)
        
        return send_file(
            BytesIO(output.getvalue()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'visitors_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
    except Exception as e:
        logger.error(f"Error exporting visitors: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to export visitors'
        }), 500

@app.route('/logout')
def logout():
    if 'user' in session:
        # Log system action
        log_system_action(session['user_id'], 'LOGOUT', 'User logged out')
        
        # Add logout notification
        add_notification(
            session['user_id'],
            'Logout Successful',
            f'You logged out at {datetime.now().strftime("%H:%M:%S")} on {datetime.now().strftime("%Y-%m-%d")}',
            'info',
            None,
            'sign-out-alt'
        )
    
    session.clear()
    return redirect(url_for('login'))

# API routes for visit requests
@app.route('/api/submit_request', methods=['POST'])
def submit_request():
    if 'user' not in session or (session['role'] != 'visitor' and session['role'] != 'agency'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        
        if not all([data.get('department'), data.get('date'), data.get('time'), data.get('purpose')]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get visitor information
        if session['role'] == 'visitor':
            cursor.execute("SELECT name FROM users WHERE username = ?", (session['user'],))
            visitor = cursor.fetchone()
            visitor_id = session['user_id']
            agency_code = None
            is_agency_visit = 0
        elif session['role'] == 'agency':
            cursor.execute("SELECT agency_name FROM agencies WHERE agency_code = ?", (session['agency_code'],))
            agency = cursor.fetchone()
            visitor = {'name': agency['agency_name']}
            visitor_id = session['user_id']
            agency_code = session['agency_code']
            is_agency_visit = 1
        
        if not visitor:
            conn.close()
            return jsonify({'success': False, 'message': 'Visitor not found'}), 404
        
        # Generate request ID
        request_id = f"VR-{datetime.now().year}-{str(uuid.uuid4())[:6].upper()}"
        
        # Insert visit request
        cursor.execute('''
        INSERT INTO visit_requests (request_id, visitor_name, visitor_id, department, date, time, purpose, status, officer, remarks, submitted_on, agency_code, is_agency_visit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request_id,
            visitor['name'],
            visitor_id,
            data.get('department'),
            data.get('date'),
            data.get('time'),
            data.get('purpose'),
            'pending',
            data.get('officer', 'To be assigned'),
            None,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            agency_code,
            is_agency_visit
        ))
        
        # Add notification for officers
        send_notification_to_role(
            'officer',
            'New Visit Request',
            f'New visit request from {visitor["name"]} for {data.get("department")} on {data.get("date")}',
            'info',
            '/dashboard/officer',
            'clipboard-list',
            'high'
        )
        
        conn.commit()
        conn.close()
        
        # Log system action
        log_system_action(visitor_id, 'SUBMIT_REQUEST', f'Visit request submitted for {data.get("department")}')
        
        # Add notification for visitor
        add_notification(
            visitor_id,
            'Visit Request Submitted',
            f'Your visit request for {data.get("department")} on {data.get("date")} has been submitted and is pending approval.',
            'info',
            None,
            'clipboard-check'
        )
        
        return jsonify({
            'success': True,
            'message': 'Visit request submitted successfully',
            'request_id': request_id
        })
        
    except Exception as e:
        logger.error(f"Submit request error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to submit request. Please try again.'
        }), 500

@app.route('/api/approve_request', methods=['POST'])
def approve_request():
    if 'user' not in session or session['role'] != 'officer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        request_id = data.get('request_id')
        
        if not request_id:
            return jsonify({'success': False, 'message': 'Request ID is required'}), 400
        
        # Update request status
        execute_db_query('''
        UPDATE visit_requests 
        SET status = 'approved', officer = ?, approved_date = ?
        WHERE request_id = ?
        ''', (session['name'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), request_id))
        
        # Get request details for notification
        request_details = execute_db_query(
            "SELECT * FROM visit_requests WHERE request_id = ?",
            (request_id,),
            fetch_one=True
        )
        
        if request_details:
            # Add notification to visitor
            add_notification(
                request_details['visitor_id'],
                'Visit Request Approved',
                f'Your visit request for {request_details["department"]} on {request_details["date"]} has been approved by {session["name"]}.',
                'success',
                None,
                'check-circle'
            )
        
        # Log system action
        log_system_action(session['user_id'], 'APPROVE_REQUEST', f'Approved visit request {request_id}')
        
        return jsonify({
            'success': True,
            'message': 'Visit request approved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error approving request: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to approve request'
        }), 500

@app.route('/api/reject_request', methods=['POST'])
def reject_request():
    if 'user' not in session or session['role'] != 'officer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        request_id = data.get('request_id')
        remarks = data.get('remarks', 'No reason provided')
        
        if not request_id:
            return jsonify({'success': False, 'message': 'Request ID is required'}), 400
        
        # Update request status
        execute_db_query('''
        UPDATE visit_requests 
        SET status = 'rejected', officer = ?, remarks = ?, rejected_date = ?
        WHERE request_id = ?
        ''', (session['name'], remarks, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), request_id))
        
        # Get request details for notification
        request_details = execute_db_query(
            "SELECT * FROM visit_requests WHERE request_id = ?",
            (request_id,),
            fetch_one=True
        )
        
        if request_details:
            # Add notification to visitor
            add_notification(
                request_details['visitor_id'],
                'Visit Request Rejected',
                f'Your visit request for {request_details["department"]} on {request_details["date"]} has been rejected by {session["name"]}. Reason: {remarks}',
                'error',
                None,
                'times-circle'
            )
        
        # Log system action
        log_system_action(session['user_id'], 'REJECT_REQUEST', f'Rejected visit request {request_id}: {remarks}')
        
        return jsonify({
            'success': True,
            'message': 'Visit request rejected successfully'
        })
        
    except Exception as e:
        logger.error(f"Error rejecting request: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to reject request'
        }), 500

# API routes for visitor verification and entry logging
@app.route('/api/verify_visitor', methods=['POST'])
def verify_visitor():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        data = request.json
        aadhaar = data.get('aadhaar')
        pass_id = data.get('pass_id')  # Can also search by pass ID
        
        visitor = None
        
        # Search by pass ID first (for worker passes)
        if pass_id:
            # Check worker passes
            worker_pass = execute_db_query(
                "SELECT wp.*, u.* FROM worker_passes wp JOIN users u ON wp.worker_id = u.user_id WHERE wp.pass_id = ? AND wp.status = 'active'",
                (pass_id,),
                fetch_one=True
            )
            if worker_pass:
                visitor = worker_pass
        
        # Search by Aadhaar (for regular visitors)
        elif aadhaar:
            if not validate_aadhaar(aadhaar):
                return jsonify({'success': False, 'message': 'Invalid Aadhaar number format'}), 400
            
            # Check if Aadhaar is blacklisted
            if is_aadhaar_blacklisted(aadhaar):
                reason = get_blacklist_reason(aadhaar)
                return jsonify({
                    'success': False,
                    'message': f'Access denied. This Aadhaar number is blacklisted. Reason: {reason}'
                }), 403
            
            # Find visitor by Aadhaar
            visitor = execute_db_query(
                "SELECT * FROM users WHERE aadhaar = ? AND role = 'visitor' AND status = 'active'",
                (aadhaar,),
                fetch_one=True
            )
        else:
            return jsonify({'success': False, 'message': 'Aadhaar number or Pass ID is required'}), 400
        
        if not visitor:
            return jsonify({
                'success': False,
                'message': 'Visitor/Worker not found or account not active'
            }), 404
        
        # Check for approved visits (for regular visitors)
        approved_visits = []
        if not pass_id:  # Only check for regular visitors
            approved_visits = execute_db_query(
                "SELECT * FROM visit_requests WHERE visitor_id = ? AND status = 'approved' AND date >= ?",
                (visitor['user_id'], datetime.now().strftime('%Y-%m-%d')),
                fetch_all=True
            )
        
        # Prepare response
        visitor_data = {
            'name': visitor['name'],
            'user_id': visitor['user_id'],
            'email': visitor['email'],
            'phone': visitor['phone'],
            'masked_aadhaar': mask_aadhaar(visitor.get('aadhaar', '')),
            'photo_url': f"/static/uploads/{visitor['photo_file']}" if visitor['photo_file'] and visitor['photo_file'] != 'placeholder.jpg' else None,
            'has_approved_visits': len(approved_visits) > 0 or bool(pass_id),
            'approved_visits': [dict(visit) for visit in approved_visits],
            'pass_id': pass_id,
            'is_worker': bool(pass_id)
        }
        
        return jsonify({
            'success': True,
            'visitor': visitor_data
        })
        
    except Exception as e:
        logger.error(f"Error verifying visitor: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to verify visitor'
        }), 500

@app.route('/api/record_entry', methods=['POST'])
def record_entry():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        pass_id = data.get('pass_id')
        visitor_id = data.get('visitor_id')
        visitor_name = data.get('visitor_name')
        department = data.get('department')
        photo_data = data.get('photo_data')
        face_match_score = data.get('face_match_score', 0.0)
        agency_code = data.get('agency_code')
        pass_type = data.get('pass_type', 'visitor')
        
        if not all([visitor_id, visitor_name, department]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Generate pass ID if not provided
        if not pass_id:
            pass_id = f"ENTRY-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        
        # Save entry photo if provided
        entry_photo = None
        if photo_data:
            entry_photo = handle_photo_upload(photo_data)
        
        # Get visitor's Aadhaar for last 4 digits
        visitor = execute_db_query(
            "SELECT aadhaar FROM users WHERE user_id = ?",
            (visitor_id,),
            fetch_one=True
        )
        
        aadhaar_last4 = None
        if visitor and visitor['aadhaar']:
            aadhaar_last4 = get_aadhaar_last4(visitor['aadhaar'])
        
        # Record entry
        execute_db_query('''
        INSERT INTO entry_logs (pass_id, visitor_name, visitor_id, department, aadhaar_last4, entry_time, status, entry_photo, face_match_score, agency_code, pass_type, security_officer, entry_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            pass_id,
            visitor_name,
            visitor_id,
            department,
            aadhaar_last4,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'inside',
            entry_photo,
            face_match_score,
            agency_code,
            pass_type,
            session['name'],
            datetime.now().strftime('%Y-%m-%d')
        ))
        
        # Log system action
        log_system_action(session['user_id'], 'RECORD_ENTRY', f'Recorded entry for {visitor_name} ({visitor_id})')
        
        # Add notification to visitor
        add_notification(
            visitor_id,
            'Entry Recorded',
            f'Your entry to {department} has been recorded. Pass ID: {pass_id}',
            'success',
            None,
            'sign-in-alt'
        )
        
        return jsonify({
            'success': True,
            'message': 'Entry recorded successfully',
            'pass_id': pass_id
        })
        
    except Exception as e:
        logger.error(f"Error recording entry: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to record entry'
        }), 500

@app.route('/api/record_exit', methods=['POST'])
def record_exit():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        pass_id = data.get('pass_id')
        
        if not pass_id:
            return jsonify({'success': False, 'message': 'Pass ID is required'}), 400
        
        # Check if entry exists and visitor is inside
        entry_log = execute_db_query(
            "SELECT * FROM entry_logs WHERE pass_id = ? AND status = 'inside'",
            (pass_id,),
            fetch_one=True
        )
        
        if not entry_log:
            return jsonify({
                'success': False,
                'message': 'Entry not found or visitor already exited'
            }), 404
        
        # Update exit time
        execute_db_query('''
        UPDATE entry_logs 
        SET exit_time = ?, status = 'exited'
        WHERE pass_id = ?
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), pass_id))
        
        # Log system action
        log_system_action(session['user_id'], 'RECORD_EXIT', f'Recorded exit for {entry_log["visitor_name"]} (Pass: {pass_id})')
        
        # Add notification to visitor
        add_notification(
            entry_log['visitor_id'],
            'Exit Recorded',
            f'Your exit from {entry_log["department"]} has been recorded.',
            'info',
            None,
            'sign-out-alt'
        )
        
        return jsonify({
            'success': True,
            'message': 'Exit recorded successfully'
        })
        
    except Exception as e:
        logger.error(f"Error recording exit: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to record exit'
        }), 500

@app.route('/api/verify_face', methods=['POST'])
def verify_face():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.json
        visitor_id = data.get('visitor_id')
        photo_data = data.get('photo_data')
        
        if not visitor_id:
            return jsonify({'success': False, 'message': 'Visitor ID is required'}), 400
        
        # Get visitor's photo from database
        visitor = execute_db_query(
            "SELECT photo_file FROM users WHERE user_id = ?",
            (visitor_id,),
            fetch_one=True
        )
        
        if not visitor:
            return jsonify({'success': False, 'message': 'Visitor not found'}), 404
        
        face_verified = False
        face_match_score = 0.0
        
        if visitor['photo_file'] and visitor['photo_file'] != 'placeholder.jpg' and photo_data:
            known_image_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor['photo_file'])
            face_match_score = compare_faces(known_image_path, photo_data)
            face_verified = face_match_score > 0.7  # Threshold for face verification
        
        return jsonify({
            'success': True,
            'face_verified': face_verified,
            'face_match_score': face_match_score
        })
        
    except Exception as e:
        logger.error(f"Error verifying face: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to verify face'
        }), 500

# API routes for notifications
@app.route('/api/mark_notification_read', methods=['POST'])
def mark_notification_read():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    notification_id = data.get('notification_id')
    
    if not notification_id:
        return jsonify({'success': False, 'message': 'Notification ID is required'}), 400
    
    try:
        execute_db_query(
            "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
            (notification_id, session['user_id'])
        )
        
        return jsonify({
            'success': True,
            'message': 'Notification marked as read'
        })
        
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to mark notification as read'
        }), 500

@app.route('/api/mark_all_notifications_read', methods=['POST'])
def mark_all_notifications_read():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        execute_db_query(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
            (session['user_id'],)
        )
        
        return jsonify({
            'success': True,
            'message': 'All notifications marked as read'
        })
        
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to mark notifications as read'
        }), 500

@app.route('/api/get_active_passes')
def get_active_passes():
    if 'user' not in session or session['role'] != 'security':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Get all active passes for today (both visitors and workers)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get approved visitor requests for today
        cursor.execute("""
        SELECT 
            vr.request_id as pass_id,
            vr.visitor_id,
            vr.visitor_name,
            'visitor' as pass_type,
            vr.department,
            vr.date,
            vr.time,
            u.photo_file,
            u.phone,
            u.email
        FROM visit_requests vr
        JOIN users u ON vr.visitor_id = u.user_id
        WHERE vr.status = 'approved' 
        AND vr.date = ?
        ORDER BY vr.time
        """, (today,))
        
        visitor_passes = cursor.fetchall()
        
        # Get active worker passes for today
        cursor.execute("""
        SELECT 
            wp.pass_id,
            wp.worker_id as visitor_id,
            wp.worker_name as visitor_name,
            wp.pass_type,
            wp.access_areas as department,
            wp.valid_from as date,
            '09:00' as time,
            u.photo_file,
            u.phone,
            u.email,
            a.agency_name
        FROM worker_passes wp
        JOIN users u ON wp.worker_id = u.user_id
        LEFT JOIN agencies a ON wp.agency_code = a.agency_code
        WHERE wp.status = 'active' 
        AND wp.valid_from <= ? 
        AND wp.valid_until >= ?
        ORDER BY wp.worker_name
        """, (today, today))
        
        worker_passes = cursor.fetchall()
        
        conn.close()
        
        # Combine and format the results
        all_passes = []
        
        # Add visitor passes
        for pass_row in visitor_passes:
            pass_dict = dict(pass_row)
            pass_dict['access_areas'] = [pass_dict['department']]
            pass_dict['pass_type_display'] = 'Visitor Pass'
            pass_dict['agency_name'] = None
            all_passes.append(pass_dict)
        
        # Add worker passes
        for pass_row in worker_passes:
            pass_dict = dict(pass_row)
            try:
                if pass_dict['department']:
                    pass_dict['access_areas'] = json.loads(pass_dict['department'])
                else:
                    pass_dict['access_areas'] = []
            except:
                pass_dict['access_areas'] = []
            pass_dict['pass_type_display'] = f"{pass_dict['pass_type'].title()} Worker Pass"
            all_passes.append(pass_dict)
        
        return jsonify({
            'success': True,
            'passes': all_passes,
            'count': len(all_passes)
        })
        
    except Exception as e:
        logger.error(f"Error getting active passes: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get active passes'
        }), 500

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True)
