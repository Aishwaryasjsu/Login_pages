from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask import session
import mysql.connector
# import pyodbc
from dotenv import load_dotenv 
import os

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# MySQL Database Configuration
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_DATABASE'),
}

# Microsoft SQL Server ODBC Connection String
# connection_string = f"Driver={os.getenv('DB_DRIVER')};Server={os.getenv('DB_SERVER')};Database={os.getenv('DB_NAME')};Uid={os.getenv('DB_UID')};Pwd={os.getenv('DB_PWD')};Encrypt={os.getenv('DB_ENCRYPT')};TrustServerCertificate={os.getenv('DB_TRUST_SERVER_CERTIFICATE')};Connection Timeout={os.getenv('DB_CONNECTION_TIMEOUT')}"
# conn = pyodbc.connect(connection_string)
# cursor = conn.cursor()

# # Create a connection to the database for mysql
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Routes
@app.route('/')
def index():
    try:
        return render_template('login.html')
    except Exception as e:
        print("Error rendering login template:", str(e))
        return str(e)

@app.route('/login', methods=['POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            # Check credentials in the database
            cursor.execute('SELECT * FROM userdetails WHERE email_id=%s', (email,))
            user = cursor.fetchone()

            if user and bcrypt.check_password_hash(user[1], password):
                session['email'] = user[0]
                return redirect(url_for('welcome'))
            else:
                 flash("Login failed. Check your email and password.", 'error')
                 return redirect(url_for('index'))
    except Exception as e:
        print("Error during login:", str(e))
        return str(e)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            # Check if password matches confirmation
            if password != confirm_password:
                flash('Password and confirm password do not match', 'error')
                return redirect(url_for('login'))

            # Hash the password before storing it in the database
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Insert new user into the database
            cursor.execute('INSERT INTO userdetails (email_id, password) VALUES (%s, %s)', (email, hashed_password))
            conn.commit()

            return render_template('login.html')

        return render_template('signup.html')
    except Exception as e:
        print("Error during signup:", str(e))
        return str(e)
    
@app.route('/welcome')
def welcome():
    # Check if the user is logged in (email is in the session)
    if 'email' in session:
        return render_template('welcome.html', email=session['email'])
    else:
        return redirect(url_for('index'))
    
@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        if request.method == 'POST':
            email = request.form['email']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if new_password == confirm_password:
                # Update the password in the database (simplified for demonstration)
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cursor.execute('UPDATE userdetails SET password=%s WHERE email_id=%s', (hashed_password, email))
                conn.commit()

                flash("Password successfully reset. You can now log in with your new password.", 'info')
                return redirect(url_for('index'))
            else:
                flash("Passwords do not match. Please try again.", 'error')
                return redirect(url_for('forgot_password'))
    except Exception as e:
        print("Error during password reset:", str(e))
        return str(e)

if __name__ == '__main__':
    app.secret_key = 'supersecretkey'
    app.run(debug=True)
