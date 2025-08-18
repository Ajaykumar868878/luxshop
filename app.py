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

# Configure logging
import logging
logging.basicConfig(level=logging.DEBUG)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this-in-production')

# Supabase setup
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'info')
        return redirect(url_for('login_page'))

    try:
        user_id = session['user_id']
        result = supabase.table('users').select('*').eq('id', user_id).single().execute()
        
        if result.data:
            user_data = result.data
            return render_template('user.html', user=user_data)
        else:
            flash('Could not retrieve user profile.', 'danger')
            session.clear()
            return redirect(url_for('login_page'))
            
    except Exception as e:
        app.logger.error(f"Error fetching user profile: {str(e)}", exc_info=True)
        flash('An error occurred while fetching your profile.', 'danger')
        return redirect(url_for('index'))    

@app.route('/wishlist')
def wishlist():
    """Serve the wishlist page"""
    return render_template('wishlist.html')

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
        
        # Check if email already exists in Supabase
        try:
            print(f"DEBUG: Checking if email {email} already exists...")
            existing_user = supabase.table('users').select('id').eq('email', email).execute()
            print(f"DEBUG: Existing user check result: {existing_user}")
            if existing_user.data:
                print(f"DEBUG: Email {email} already exists")
                return jsonify({'success': False, 'errors': ['Email already registered.']}), 400
            print(f"DEBUG: Email {email} is available")
        except Exception as e:
            print(f"DEBUG: Error checking existing user: {str(e)}")
            print(f"DEBUG: Exception type: {type(e).__name__}")
            return jsonify({'success': False, 'errors': ['Database connection error. Please try again.']}), 500
        
        # Create new user in Supabase
        password_hash = hash_password(password)
        app.logger.debug(f"Creating new user with email: {email}")
        try:
            user_data = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'phone': phone,
                'password_hash': password_hash
            }
            app.logger.debug(f"User data to insert: {user_data}")
            
            result = supabase.table('users').insert(user_data).execute()
            app.logger.debug(f"Insert result: {result}")
            app.logger.debug(f"Insert result data: {result.data}")
            app.logger.debug(f"Insert result count: {result.count}")
            
            if result.data:
                app.logger.debug(f"User created successfully: {result.data}")
                return jsonify({'success': True, 'message': 'Account created successfully!'})
            else:
                app.logger.debug(f"Insert failed - no data returned")
                app.logger.debug(f"Full result object: {vars(result)}")
                return jsonify({'success': False, 'errors': ['Failed to create account. Please try again.']}), 500
                
        except Exception as e:
            app.logger.error(f"Exception during user creation: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'errors': ['Failed to create account. Please try again.']}), 500
        
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
        
        # Check credentials with Supabase
        try:
            result = supabase.table('users').select('id, first_name, last_name, email, password_hash').eq('email', email).execute()
            app.logger.debug(f"Login check for {email}: {result}")

            if not result.data:
                return jsonify({'success': False, 'errors': ['Invalid email or password.']}), 401

            user = result.data[0]
            
            if user['password_hash'] != hash_password(password):
                return jsonify({'success': False, 'errors': ['Invalid email or password.']}), 401

            # Create session
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            session['user_email'] = user['email']

        except Exception as e:
            app.logger.error(f"Exception during login: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'errors': ['An error occurred during login. Please try again.']}), 500
        
        return jsonify({
            'success': True, 
            'message': 'Login successful! Redirecting...',
            'user': {
                'name': session['user_name'],
                'email': session['user_email']
            },
            'redirect_url': url_for('index')
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

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    """Handle user profile updates"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'errors': ['Authentication required.']}), 401

    try:
        data = request.get_json()
        user_id = session['user_id']

        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        phone = data.get('phone', '').strip()
        birthdate = data.get('birthdate')
        bio = data.get('bio', '').strip()

        errors = []
        if not first_name:
            errors.append('First name is required.')
        if not last_name:
            errors.append('Last name is required.')
        if phone and not validate_phone(phone):
            errors.append('Invalid phone number format.')

        if errors:
            return jsonify({'success': False, 'errors': errors}), 400

        update_data = {
            'first_name': first_name,
            'last_name': last_name,
            'phone': phone,
            'birthdate': birthdate,
            'bio': bio
        }

        try:
            result = supabase.table('users').update(update_data).eq('id', user_id).execute()

            if result.data:
                session['user_name'] = f"{first_name} {last_name}"
                return jsonify({'success': True, 'message': 'Profile updated successfully!'})
            else:
                return jsonify({'success': False, 'errors': ['Failed to update profile. Please try again.']}), 500

        except Exception as e:
            app.logger.error(f"Exception during profile update: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'errors': ['An error occurred during the update.']}), 500

    except Exception as e:
        app.logger.error(f"Exception in update_profile: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'errors': ['An unexpected error occurred.']}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'errors': ['Internal server error']}), 500

if __name__ == '__main__':
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)