from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from functools import wraps
import hashlib
import os
from datetime import datetime
import re
from dotenv import load_dotenv
from supabase import create_client, Client
import gotrue

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

def no_cache(f):
    """Decorator to prevent caching of protected pages."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function

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
@app.route('/index')
@app.route('/')
def index():
    """Serve the home page"""
    user_data = None
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            result = supabase.table('users').select('first_name', 'last_name').eq('id', user_id).single().execute()
            if result.data:
                user_data = result.data
        except Exception as e:
            app.logger.error(f"Error fetching user data for index page: {str(e)}", exc_info=True)
    return render_template('index.html', user=user_data)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Handle login page and authentication"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password.', 'error')
            return redirect(url_for('login_page'))
            
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            # Check user credentials
            result = supabase.table('users').select('*').eq('email', email).eq('password', hashed_password).single().execute()
            
            if result.data:
                user = result.data
                session['user_id'] = user['id']
                session['email'] = user['email']
                flash('Login successful!', 'success')
                return redirect(url_for('user'))
            else:
                flash('Invalid email or password.', 'error')
                return redirect(url_for('login_page'))
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'error')
            return redirect(url_for('login_page'))
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """Handle user registration"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        if not email or not password or not name:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('signup_page'))
            
        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('signup_page'))
            
        try:
            # Check if user already exists
            existing_user = supabase.table('users').select('id').eq('email', email).single().execute()
            if existing_user.data:
                flash('Email already registered.', 'error')
                return redirect(url_for('signup_page'))
                
            # Hash the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # Create new user
            new_user = {
                'email': email,
                'password': hashed_password,
                'name': name
            }
            
            result = supabase.table('users').insert(new_user).execute()
            
            if result.data:
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login_page'))
            else:
                flash('Registration failed.', 'error')
                return redirect(url_for('signup_page'))
                
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration.', 'error')
            return redirect(url_for('signup_page'))
            
    return render_template('signup.html')

@app.route('/forgot-password')
def forgot_password_page():
    """Serve the forgot password page"""
    return render_template('forgot-password.html')

@app.route('/reset-password')
def reset_password_page():
    """Serve the reset password page"""
    return render_template('reset-password.html')

@app.route('/shop')
def shop():
    """Serve the shop page with products from the database"""
    try:
        response = supabase.table('products').select('*').order('id').execute()
        products = response.data if hasattr(response, 'data') and response.data else []
        return render_template('shop.html', products=products)
    except Exception as e:
        app.logger.error(f"Error fetching products for shop page: {str(e)}", exc_info=True)
        flash('Could not load products. Please try again later.', 'danger')
        return render_template('shop.html', products=[])

@app.route('/about')
def about():
    """Serve the about page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/cart')
@no_cache
def cart_page():
    cart_session = session.get('cart', {})
    cart_items = []
    subtotal = 0

    if cart_session:
        product_ids = [int(pid) for pid in cart_session.keys()]
        
        # Fetch product details from Supabase
        response = supabase.table('products').select('id, name, price, image_url').in_('id', product_ids).execute()

        if hasattr(response, 'data') and response.data:
            products_data = {str(p['id']): p for p in response.data}
            
            for product_id_str, quantity in cart_session.items():
                product_info = products_data.get(product_id_str)
                if product_info:
                    total_price = product_info['price'] * quantity
                    subtotal += total_price
                    cart_items.append({
                        'id': product_id_str,
                        'name': product_info['name'],
                        'price': product_info['price'],
                        'image_url': product_info['image_url'],
                        'quantity': quantity,
                        'total_price': total_price
                    })

    # Basic calculations
    shipping = 9.99 if subtotal > 0 else 0
    tax = subtotal * 0.08
    total = subtotal + shipping + tax

    return render_template('cart.html', cart_items=cart_items, subtotal=subtotal, shipping=shipping, tax=tax, total=total)

@app.route('/user')
@no_cache
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

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/wishlist')
@no_cache
def wishlist():
    """Serve the wishlist page with the user's items"""
    if 'user_id' not in session:
        flash('Please log in to view your wishlist.', 'info')
        return redirect(url_for('login_page'))

    try:
        user_id = session['user_id']
        
        # Get product IDs from user's wishlist
        wishlist_response = supabase.table('wishlist').select('product_id').eq('user_id', user_id).execute()
        
        if not wishlist_response.data:
            # Render wishlist with no items if it's empty
            return render_template('wishlist.html', wishlist_items=[])

        product_ids = [item['product_id'] for item in wishlist_response.data]
        
        # Fetch product details for the wishlist items
        # This assumes you have a 'products' table with product details
        products_response = supabase.table('products').select('*').in_('id', product_ids).execute()
        
        wishlist_items = products_response.data if products_response.data else []
            
        return render_template('wishlist.html', wishlist_items=wishlist_items)

    except Exception as e:
        app.logger.error(f"Error fetching wishlist page: {str(e)}", exc_info=True)
        flash('An error occurred while fetching your wishlist.', 'danger')
        return render_template('wishlist.html', wishlist_items=[])


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
@app.route('/api/login', methods=['POST'])
def handle_login():
    """Handle unified login for all roles."""
    try:
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'user') # Default to 'user' if not provided

        if not all([email, password, role]):
            return jsonify({'success': False, 'errors': ['Email, password, and role are required.']}), 400

        # Authenticate with Supabase Auth
        auth_response = supabase.auth.sign_in_with_password({
            'email': email,
            'password': password
        })
        
        user = auth_response.user

        # Fetch user details from 'users' table to check the role
        user_details = supabase.table('users').select('id, role').eq('id', user.id).single().execute().data
        
        if not user_details:
            return jsonify({'success': False, 'errors': ['User profile not found.']}), 404

        user_role = user_details.get('role', 'user')

        # Verify that the user's stored role matches the role they are trying to log in as
        if user_role != role:
            return jsonify({'success': False, 'errors': [f'You do not have permission to log in as a {role}.']}), 403

        # Set session variables
        session['user_id'] = user.id
        session['user_role'] = user_role
        session['email'] = user.email

        # Determine redirect URL based on role
        if user_role == 'admin':
            redirect_url = url_for('admin_dashboard')
        elif user_role == 'seller':
            redirect_url = url_for('seller_dashboard') # Assuming a seller dashboard exists
        else:
            redirect_url = url_for('user') # Default user profile page

        return jsonify({
            'success': True, 
            'message': 'Login successful!', 
            'redirect_url': redirect_url
        })

    except gotrue.errors.AuthApiError as e:
        return jsonify({'success': False, 'errors': ['Invalid email or password.']}), 401
    except Exception as e:
        app.logger.error(f"Exception during login: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'errors': ['An unexpected error occurred. Please try again.']}), 500

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
        role = data.get('role', 'user')
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
            errors.append('Invalid phone number format.')

        if errors:
            return jsonify({'success': False, 'errors': errors}), 400

        # Check if email already exists in Supabase
        try:
            existing_user = supabase.table('users').select('id').eq('email', email).execute()
            if existing_user.data:
                return jsonify({'success': False, 'errors': ['Email already registered.']}), 400
        except Exception as e:
            return jsonify({'success': False, 'errors': ['Database connection error. Please try again.']}), 500
        
        # Create new user in Supabase
        app.logger.debug(f"Creating new user with email: {email}")
        try:
            # Create user in Supabase Auth
            auth_response = supabase.auth.sign_up({
                'email': email,
                'password': password
            })
            
            # Get the user_id from the auth response
            user_id = auth_response.user.id

            user_data = {
                'id': user_id,  # Use the id from auth.users
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'phone': phone,
                'role': role
            }
            app.logger.debug(f"User data to insert: {user_data}")
            
            result = supabase.table('users').insert(user_data).execute()
            app.logger.debug(f"Insert result: {result}")
            app.logger.debug(f"Insert result data: {result.data}")
            
            if result.data:
                app.logger.debug(f"User created successfully: {result.data}")
                return jsonify({
                    'success': True,
                    'message': 'Account created successfully! Please check your email to verify your account before logging in.'
                })
            else:
                app.logger.debug(f"Insert failed - no data returned")
                return jsonify({'success': False, 'errors': ['Failed to create account. Please try again.']}), 500
                
        except Exception as e:
            app.logger.error(f"Exception during user creation: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'errors': ['Failed to create account. Please try again.']}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'errors': ['An error occurred. Please try again.']}), 500

@app.route('/api/update_password', methods=['POST'])
def update_password():
    """Handle password updates"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'errors': ['Authentication required.']}), 401

    try:
        data = request.get_json()
        user_id = session['user_id']

        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not all([current_password, new_password]):
            return jsonify({'success': False, 'errors': ['All fields are required.']}), 400

        # Verify current password
        try:
            user = User.query.get(user_id)
            if user and user.check_password(current_password):
                # Hash and update the new password
                user.set_password(new_password)
                db.session.commit()
                app.logger.info(f"User {user.id} updated their password successfully.")
                return jsonify({'success': True, 'message': 'Password updated successfully.'})
        except Exception as e:
            app.logger.error(f"Database error during password update for user {session.get('user_id')}: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'errors': ['A database error occurred.']}), 500

    except Exception as e:
        app.logger.error(f"Exception in update_password: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'errors': ['An unexpected error occurred.']}), 500

# ===============================================
# Admin Routes
# ===============================================

@app.route('/adminlog')
def admin_login_page():
    """Serve the admin login page"""
    return render_template('adminlog.html')

@app.route('/api/admin/login', methods=['POST'])
def handle_admin_login():
    """Handle admin login form submission"""
    try:
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # IMPORTANT: Hardcoded admin credentials. Replace with a secure check against a database.
        if email == 'admin@luxeshop.com' and password == 'admin':
            session['admin_logged_in'] = True
            app.logger.info(f"Admin user {email} logged in successfully")
            return jsonify({
                'success': True,
                'message': 'Admin login successful! Redirecting...',
                'redirect_url': url_for('admin_dashboard')
            })
        else:
            app.logger.warning(f"Failed admin login attempt for email: {email}")
            return jsonify({'success': False, 'errors': ['Invalid admin credentials.']}), 401

    except Exception as e:
        app.logger.critical(f"Unexpected error in admin login handler: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'errors': [f'An unexpected error occurred: {str(e)}']}), 500

@app.route('/admindash')
@no_cache
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Please log in as an admin to view this page.', 'error')
        return redirect(url_for('admin_login_page'))
    return render_template('admindash.html')

@app.route('/sellerdash')
@no_cache
def seller_dashboard():
    """Serve the seller dashboard, showing products and revenue."""
    if session.get('user_role') != 'seller':
        flash('You must be logged in as a seller to view this page.', 'error')
        return redirect(url_for('login_page'))
    
    seller_id = session.get('user_id')
    if not seller_id:
        flash('Your session has expired. Please log in again.', 'error')
        return redirect(url_for('login_page'))

    products = []
    total_revenue = 0
    try:
        # Fetch products for the seller
        product_response = supabase.table('products').select('*').eq('seller_id', seller_id).order('created_at', desc=True).execute()
        if hasattr(product_response, 'data') and product_response.data:
            products = product_response.data

        # Calculate total revenue from completed orders
        order_items_response = supabase.table('order_items').select('quantity, price_at_purchase').eq('seller_id', seller_id).execute()
        if hasattr(order_items_response, 'data') and order_items_response.data:
            for item in order_items_response.data:
                total_revenue += item['quantity'] * item['price_at_purchase']

    except Exception as e:
        app.logger.error(f"Error loading seller dashboard for {seller_id}: {str(e)}", exc_info=True)
        flash('Could not load all dashboard data. Please try again later.', 'danger')

    return render_template('sellerdash.html', products=products, total_revenue=total_revenue)

# ===============================================
# Seller API Routes
# ===============================================

@app.route('/api/seller/products/add', methods=['POST'])
@no_cache
def handle_add_product():
    """Handle the 'Add Product' form submission from the seller dashboard."""
    if session.get('user_role') != 'seller':
        return jsonify({'success': False, 'errors': ['You must be logged in as a seller.']}), 403

    try:
        data = request.get_json()
        seller_id = session.get('user_id')

        # Validate incoming data
        name = data.get('name')
        description = data.get('description')
        price_str = data.get('price')
        stock_quantity_str = data.get('stock_quantity')
        image_url = data.get('image_url')

        errors = []
        if not all([name, description, price_str, stock_quantity_str, image_url]):
            errors.append('All fields are required.')

        price = 0
        try:
            price = float(price_str)
            if price <= 0:
                errors.append('Price must be a positive number.')
        except (ValueError, TypeError):
            errors.append('Price must be a valid number.')

        stock_quantity = 0
        try:
            stock_quantity = int(stock_quantity_str)
            if stock_quantity < 0:
                errors.append('Stock quantity must be a non-negative integer.')
        except (ValueError, TypeError):
            errors.append('Stock quantity must be a valid integer.')

        if errors:
            return jsonify({'success': False, 'errors': errors}), 400

        # Prepare product data for insertion
        product_data = {
            'seller_id': seller_id,
            'name': name,
            'description': description,
            'price': price,
            'stock_quantity': stock_quantity,
            'image_url': image_url
        }

        # Insert into Supabase
        result = supabase.table('products').insert(product_data).execute()

        if result.data:
            return jsonify({'success': True, 'message': 'Product added successfully!'})
        else:
            return jsonify({'success': False, 'errors': ['Failed to add product to the database.']}), 500

    except Exception as e:
        app.logger.error(f"Error adding product: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'errors': ['An unexpected server error occurred.']}), 500

# ===============================================
# Main Application Runner
# ===============================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)