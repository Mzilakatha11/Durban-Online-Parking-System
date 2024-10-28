from flask import Flask, request, render_template, redirect, url_for, session, flash
from new_parking import Parking_Hours  # Ensure your class is in parking_hours.py
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret key for session management
app.secret_key = 'your_secret_key_here'  # Update this to a secure key in production

# Simulated user database (in memory for now)
users = {}
user_emails = {}  # Simulate email storage for password recovery

# Database connection function
def connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="thabisosandiswa5",
            password="Thabiso@2001",
            database="online_parking_system"
        )
        print("Database has been connected successfully")
        return conn
    except mysql.connector.Error as error:
        print(f"Connection failed: {error}")
        return None

# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username or email already exists
        if username in users:
            flash('Username already exists. Please choose a different one.', 'danger')
        elif email in user_emails.values():
            flash('Email already in use. Please use a different one.', 'danger')
        else:
            # Hash the password and store the user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users[username] = hashed_password
            user_emails[username] = email  # Store user's email

            # Save user to the database
            db = connection()
            cursor = db.cursor()
            sql = "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)"
            cursor.execute(sql, (username, hashed_password, email))
            db.commit()
            cursor.close()
            db.close()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists and password is correct
        if username in users and bcrypt.check_password_hash(users[username], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the user from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Index route - ensure login required for accessing parking calculation
@app.route('/')
def index():
    if 'username' in session:  # Check if user is logged in
        return render_template('index.html')
    else:
        flash('Please log in to access the parking system.', 'warning')
        return redirect(url_for('login'))

# Parking calculation route
@app.route('/calculate', methods=['POST'])
def calculate():
    if 'username' not in session:
        flash('Please log in to calculate parking fees.', 'warning')
        return redirect(url_for('login'))
    
    db = connection()
    cursor = db.cursor()

    username = session['username']
    name = request.form['name']
    car_registration_number = request.form['car_registration_number']
    parking_rate = float(request.form.get('parking_rate', 14))
    duration_type = request.form['duration_type']
    duration_value = float(request.form['duration_value'])

    parking = Parking_Hours(username, car_registration_number, parking_rate)

    if duration_type == 'hours':
        cost = parking.hours_parking(duration_value)
    elif duration_type == 'days':
        cost = parking.daily_parking(duration_value)
    elif duration_type == 'months':
        cost = parking.monthly_parking(duration_value)
    elif duration_type == 'years':
        cost = parking.yearly_parking(duration_value)
    else:
        cost = None

    if cost is None:
        return "Error: Invalid input or calculation."
    
    # Save the parking record linked to the user
    sql = "INSERT INTO parking_system (username,name, car_registration_number, duration_type, duration_value, cost) VALUES (%s,%s, %s, %s, %s, %s)"
    values = (username,name, car_registration_number, duration_type, duration_value, cost)
    cursor.execute(sql, values)
    db.commit()
    cursor.close()
    db.close()

    return render_template('results.html',
                           name=name,
                           username=username,
                           car_registration_number=car_registration_number,
                           parking_rate=parking_rate,
                           duration_type=duration_type,
                           duration_value=duration_value,
                           cost=cost)

# Forgotten Username route
@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    if request.method == 'POST':
        email = request.form['email']

        # Find the username based on the provided email
        username = next((user for user, mail in user_emails.items() if mail == email), None)

        if username:
            flash(f'Your username is: {username}', 'info')
        else:
            flash('Email not found. Please check and try again.', 'danger')

    return render_template('forgot_username.html')

# Forgotten Password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']

        # Check if the user exists
        if username in users:
            # Generate a new password (In a real system, send an email with a reset link)
            new_password = 'new_password123'  # Example of new password generation
            users[username] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Update the password in the database
            db = connection()
            cursor = db.cursor()
            sql = "UPDATE users SET password_hash = %s WHERE username = %s"
            cursor.execute(sql, (users[username], username))
            db.commit()
            cursor.close()
            db.close()

            flash(f'Your new password is: {new_password}. Please change it after logging in.', 'info')
        else:
            flash('Username not found. Please check and try again.', 'danger')

    return render_template('forgot_password.html')

# Before request handler to ensure login required for most routes
@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'forgot_username', 'forgot_password']
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect(url_for('login'))

# Adding a logout button on the right top when user is logged in
@app.context_processor
def inject_user():
    return dict(logged_in=('username' in session))

# Route to view user parking records
@app.route('/user_parking_records')
def user_parking_records():
    if 'username' not in session:
        flash('Please log in to view your parking records.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    db = connection()
    cursor = db.cursor()
    sql = "SELECT * FROM parking_system WHERE username = %s"
    cursor.execute(sql, (username,))
    records = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('user_parking_records.html', records=records)

if __name__ == '__main__':
    app.run(debug=True)




