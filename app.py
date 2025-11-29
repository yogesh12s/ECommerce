import os
import random
import string
import base64
import hashlib
import json
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "secure_key_aura_shop"

# --- DATABASE CONFIG ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aura_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- EMAIL CONFIG (GMAIL) ---
# NOTE: Generate App Password from Google Account > Security > 2-Step Verification > App Passwords
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yogeshgokul372@gmail.com'  # <--- REPLACE THIS
app.config['MAIL_PASSWORD'] = 'rlph chai nini ezrk'   # <--- PASTE YOUR 16-DIGIT APP PASSWORD HERE

mail = Mail(app)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- PHONEPE CREDENTIALS ---
MERCHANT_ID = "PGTESTPAYUAT"
SALT_KEY = "099eb0cd-02cf-4e2a-8aca-3e6c6aff0399"
SALT_INDEX = 1
PHONEPE_BASE_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox"

# ==========================================
# MODELS
# ==========================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Integer)
    image = db.Column(db.String(500))
    category = db.Column(db.String(50))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer)
    status = db.Column(db.String(50), default='Pending') # Pending, Paid, Failed
    transaction_id = db.Column(db.String(100))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    
    # --- NEW FIELDS FOR CHECKOUT ---
    mobile = db.Column(db.String(15))
    address = db.Column(db.Text)
    
    # --- SHIPMENT TRACKING ---
    delivery_status = db.Column(db.String(50), default='Processing')
    tracking_id = db.Column(db.String(100), nullable=True)
    courier_name = db.Column(db.String(100), nullable=True)

    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_name = db.Column(db.String(100))
    price = db.Column(db.Integer)
    quantity = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def send_otp_email(email, otp):
    try:
        msg = Message('Your Verification Code - Aura', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is: {otp}. It is valid for 10 minutes."
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

# ==========================================
# AUTH & FORGOT PASSWORD ROUTES
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('home'))
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('signup'))
            
        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(name=name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
        
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- FORGOT PASSWORD FLOW ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            otp = str(random.randint(100000, 999999))
            # Store OTP in session
            session['reset_data'] = {'email': email, 'otp': otp}
            if send_otp_email(email, otp):
                flash(f'OTP sent to {email}')
                return redirect(url_for('verify_reset_otp'))
            else:
                flash('Error sending email. Check configuration.')
        else:
            flash('Email not found in our system.')
            
    return render_template('forgot_password.html')

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_data' not in session:
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == session['reset_data']['otp']:
            session['can_reset'] = True # Security Flag
            return redirect(url_for('reset_new_password'))
        else:
            flash('Invalid OTP. Please try again.')
            
    return render_template('verify_otp.html', purpose='reset')

@app.route('/reset_new_password', methods=['GET', 'POST'])
def reset_new_password():
    if not session.get('can_reset'):
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_pass = request.form.get('password')
        email = session['reset_data']['email']
        
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(new_pass, method='scrypt')
        db.session.commit()
        
        # Cleanup
        session.pop('reset_data', None)
        session.pop('can_reset', None)
        
        flash('Password Reset Successfully. Please Login.')
        return redirect(url_for('login'))
        
    return render_template('reset_password_final.html')

# ==========================================
# SHOPPING & CHECKOUT ROUTES
# ==========================================

@app.route('/')
def home():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session: session['cart'] = {}
    cart = session['cart']
    str_id = str(product_id)
    cart[str_id] = cart.get(str_id, 0) + 1
    session.modified = True
    return redirect(url_for('home'))

@app.route('/cart')
def view_cart():
    cart = session.get('cart', {})
    cart_items = []
    total = 0
    for pid, qty in cart.items():
        p = Product.query.get(pid)
        if p:
            total += p.price * qty
            cart_items.append({'product': p, 'qty': qty, 'item_total': p.price * qty})
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/checkout_page', methods=['GET'])
@login_required
def checkout_page():
    cart = session.get('cart', {})
    if not cart: return redirect(url_for('home'))
    
    # Calculate Total for Display
    total = 0
    for pid, qty in cart.items():
        p = Product.query.get(pid)
        if p: total += p.price * qty
            
    return render_template('checkout.html', total=total)

@app.route('/initiate_payment', methods=['POST'])
@login_required
def initiate_payment():
    cart = session.get('cart', {})
    if not cart: return redirect(url_for('home'))
    
    # 1. Get Details from Checkout Form
    mobile = request.form.get('mobile')
    address = request.form.get('address')
    
    # 2. Calculate Total & Prepare Order Items
    total = 0
    order_items = []
    for pid, qty in cart.items():
        p = Product.query.get(pid)
        if p:
            total += p.price * qty
            order_items.append(OrderItem(product_name=p.name, price=p.price, quantity=qty))

    # 3. Create Order in Database (Status: Pending)
    txn_id = "TXN" + datetime.now().strftime("%Y%m%d%H%M%S") + str(current_user.id)
    new_order = Order(
        user_id=current_user.id, 
        amount=total, 
        transaction_id=txn_id, 
        items=order_items,
        mobile=mobile,    # <--- SAVING MOBILE
        address=address   # <--- SAVING ADDRESS
    )
    db.session.add(new_order)
    db.session.commit()

    # 4. PhonePe Integration
    amount_in_paise = total * 100
    payload = {
        "merchantId": MERCHANT_ID,
        "merchantTransactionId": txn_id,
        "merchantUserId": f"USER_{current_user.id}",
        "amount": amount_in_paise,
        "redirectUrl": f"{request.host_url}payment/callback",
        "redirectMode": "POST",
        "callbackUrl": f"{request.host_url}payment/callback",
        "mobileNumber": mobile,  # <--- PASSING MOBILE TO GATEWAY
        "paymentInstrument": { "type": "PAY_PAGE" }
    }

    base64_payload = base64.b64encode(json.dumps(payload).encode()).decode()
    data_to_hash = base64_payload + "/pg/v1/pay" + SALT_KEY
    checksum = hashlib.sha256(data_to_hash.encode()).hexdigest() + "###" + str(SALT_INDEX)
    
    headers = { "Content-Type": "application/json", "X-VERIFY": checksum }

    try:
        response = requests.post(f"{PHONEPE_BASE_URL}/pg/v1/pay", json={"request": base64_payload}, headers=headers)
        resp_data = response.json()
        if resp_data.get("success"):
            return redirect(resp_data["data"]["instrumentResponse"]["redirectInfo"]["url"])
        else:
            return f"Gateway Error: {resp_data.get('message')}"
    except Exception as e:
        return f"System Error: {str(e)}"

@app.route('/payment/callback', methods=['POST'])
def payment_callback():
    data = request.form
    txn_id = data.get('merchantTransactionId')
    order = Order.query.filter_by(transaction_id=txn_id).first()
    
    if order:
        if data.get('code') == 'PAYMENT_SUCCESS':
            order.status = 'Paid'
            session.pop('cart', None)
            msg = 'Success'
        else:
            order.status = 'Failed'
            msg = 'Failed'
        db.session.commit()
    else:
        msg = 'Error'
        
    return render_template('status.html', status=msg, txn_id=txn_id)

# --- ADMIN (Simple view) ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin: return redirect(url_for('home'))
    orders = Order.query.order_by(Order.date_created.desc()).all()
    products = Product.query.all()
    return render_template('admin.html', orders=orders, products=products)

# --- DB INIT ---
def init_db():
    with app.app_context():
        db.create_all()
        # Admin
        if not User.query.filter_by(email='admin@aura.com').first():
            db.session.add(User(name='Admin', email='admin@aura.com', password=generate_password_hash('admin123', method='scrypt'), is_admin=True))
        # Dummy Product
        if not Product.query.first():
            db.session.add(Product(name="Gold Hoops", price=499, image="https://images.unsplash.com/photo-1617038220319-276d3cfab638?w=600", category="Earrings"))
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)