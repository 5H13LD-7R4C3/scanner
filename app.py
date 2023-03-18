from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_bcrypt import Bcrypt
import sqlite3
import subprocess

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Set up SQLite database
conn = sqlite3.connect('scans.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
          CREATE TABLE IF NOT EXISTS scans
          (id INTEGER PRIMARY KEY AUTOINCREMENT,
           user_id INTEGER,
           ip_address TEXT,
           port_number TEXT,
           nmap_output TEXT,
           datetime TEXT)
          ''')
conn.commit()

# Routes

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Insert user into database
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  (username, hashed_password))
        conn.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        
        # Check if user exists
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if user and bcrypt.check_password_hash(user[2], password):
            # Log user in
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please log in to access this page')
        return redirect(url_for('login'))
    
    # Get user's scans from database
    c.execute("SELECT * FROM scans WHERE user_id = ?", (session['user_id'],))
    scans = c.fetchall()
    
    return render_template('dashboard.html', scans=scans)
@app.route('/scan', methods=['POST'])
@login_required
def scan():
    ip_address = request.form['ip_address']
    port_number = request.form['port_number']
    add_to_db = request.form.get('add_to_db', False)

    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

    # Validate port number
    if not (isinstance(port_number, int) and 0 <= port_number <= 65535):
        return jsonify({'error': 'Invalid port number'}), 400

    # Run Nmap scan using vuln script
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, str(port_number), '-sS --script vuln')
    report = scanner[ip_address].get('scan')

    # Save scan to database
    if add_to_db:
        scan_data = {
            'ip_address': ip_address,
            'port_number': port_number,
            'scan_date': datetime.utcnow(),
            'scan_results': report
        }
        db.session.add(Scan(**scan_data))
        db.session.commit()

    return jsonify({'report': report})
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(255))
    port_number = db.Column(db.Integer)
    scan_date = db.Column(db.DateTime)
    scan_results = db.Column(db.Text)

    def __repr__(self):
        return f'Scan(id={self.id}, ip_address={self.ip_address}, port_number={self.port_number}, scan_date={self.scan_date})'

@app.before_first_request
def setup_database():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))

        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))

    return render_template('login.html', title='Log In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)
@app.route('/scans')
@login_required
def scan_list():
    scans = Scan.query.all()
    return render_template('scan_list.html', title='Scan List', scans=sc
