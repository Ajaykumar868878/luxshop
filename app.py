from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import hashlib
import os
from datetime import datetime
import re
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this-in-production')

# Supabase setup
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Database setup (keeping SQLite as fallback)
DATABASE = 'luxeshop.db'

def init_db():
    """Initialize the database with users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email):
    """Validate email format"""
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format"""
    # Remove spaces, hyphens, parentheses
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    pattern = r'^[\+]?[1-9][\d]{0,15}$'
    return re.match(pattern, clean_phone) is not None

def test_supabase_connection():
    """Test Supabase connection"""
    try:
        # Try to get a simple response from Supabase
        response = supabase.table('users').select('*').limit(1).execute()
        return True, "Supabase connection successful"
    except Exception as e:
        return False, f"Supabase connection failed: {str(e)}"

# Routes for serving HTML pages
@app.route('/')
def index():
    """Serve the home page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Serve the login page"""
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    """Serve the signup page"""
    return render_template('signup.html')

@app.route('/shop')
def shop():
    """Serve the shop page"""
    return render_template('shop.html')

@app.route('/about')
def about():
    """Serve the about page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Serve the contact page"""
    return render_template('contact.html')

@app.route('/user')
def user():
    """Serve the user page"""
    return render_template('user.html')    

@app.route('/cart')
def cart():
    """Serve the cart page"""
    return render_template('cart.html')

@app.route('/test-supabase')
def test_supabase():
    """Test Supabase connection endpoint"""
    success, message = test_supabase_connection()
    return jsonify({
        'success': success,
        'message': message,
        'supabase_url': SUPABASE_URL,
        'env_loaded': os.getenv('SUPABASE_URL') is not None
    })



# API endpoints for form handling
@app.route('/api/signup', methods=['POST'])
def handle_signup():
    """Handle signup form submission"""
    try:
        # Get form data
        data = request.get_json() if request.is_json else request.form
        
        first_name = data.get('firstName', '').strip()
        last_name = data.get('lastName', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirmPassword', '')
        terms = data.get('terms')
        
        # Validation
        errors = []
        
        if not all([first_name, last_name, email, phone, password, confirm_password]):
            errors.append('All fields are required.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        
        if not validate_email(email):
            errors.append('Please enter a valid email address.')
        
        if not validate_phone(phone):
            errors.append('Please enter a valid phone number.')
        
        if not terms:
            errors.append('You must agree to the Terms of Service and Privacy Policy.')
        
        if errors:
            return jsonify({'success': False, 'errors': errors}), 400
        
        # Check if email already exists
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'errors': ['Email already registered.']}), 400
        
        # Create new user
        password_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, phone, password_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (first_name, last_name, email, phone, password_hash))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Account created successfully!'})
        
    except Exception as e:
        return jsonify({'success': False, 'errors': ['An error occurred. Please try again.']}), 500

@app.route('/api/login', methods=['POST'])
def handle_login():
    """Handle login form submission"""
    try:
        # Get form data
        data = request.get_json() if request.is_json else request.form
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not email or not password:
            return jsonify({'success': False, 'errors': ['Email and password are required.']}), 400
        
        # Check credentials
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, first_name, last_name, email, password_hash 
            FROM users WHERE email = ?
        ''', (email,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[4] != hash_password(password):
            return jsonify({'success': False, 'errors': ['Invalid email or password.']}), 401
        
        # Create session
        session['user_id'] = user[0]
        session['user_name'] = f"{user[1]} {user[2]}"
        session['user_email'] = user[3]
        
        return jsonify({
            'success': True, 
            'message': 'Login successful!',
            'user': {
                'name': session['user_name'],
                'email': session['user_email']
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'errors': ['An error occurred. Please try again.']}), 500

@app.route('/api/logout', methods=['POST'])
def handle_logout():
    """Handle user logout"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully!'})

@app.route('/api/user')
def get_user():
    """Get current user information"""
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'user': {
                'name': session['user_name'],
                'email': session['user_email']
            }
        })
    else:
        return jsonify({'logged_in': False})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'errors': ['Internal server error']}), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)