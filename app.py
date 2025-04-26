from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash
import random
import re

# Removed CSRF and Limiter imports

def is_strong_password(password):
    # Minimum 8 characters, 1 uppercase, 1 lowercase, 1 digit, 1 special character
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[@$!%*?&]', password)):
        return False
    return True

# Initialize app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:5612@localhost/data'

# Mail Configuration (your sending Gmail credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your-main-gmail@gmail.com'  # Your website Gmail
app.config['MAIL_PASSWORD'] = 'your-app-password'          # App password from Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'your-main-gmail@gmail.com'

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)

app.secret_key = '5162'

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create tables
with app.app_context():
    db.create_all()

# Helpers
def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('account.html', user=user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        if not email.endswith('@gmail.com'):
            flash('Only Gmail addresses are accepted.', 'danger')
            return redirect(url_for('forgot_password'))

        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            session['otp'] = otp
            session['user_email'] = user.email

            try:
                send_email('Your OTP Code', user.email, f'Your OTP is {otp}')
                flash('OTP sent to your Gmail address!', 'success')
                return redirect(url_for('verify_otp'))
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Failed to send OTP. Please try again.', 'danger')
                return redirect(url_for('forgot_password'))
        else:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            flash('OTP verified! Now reset your password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Incorrect OTP, please try again.', 'danger')
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))

        user_email = session.get('user_email')
        user = User.query.filter_by(email=user_email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()

            session.pop('otp', None)
            session.pop('user_email', None)

            flash('Password reset successful. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html')

@app.route('/premium')
def premium():
    return render_template('premium.html')

@app.route('/download')
def download():
    return render_template('download.html')

@app.route('/categories')
def categories():
    return render_template('categories.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Logged in successfully!", "success")
            return redirect(url_for("account"))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(name=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully!", "success")
        return redirect(url_for("login"))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

# Run app
if __name__ == '__main__':
    app.run(debug=True)
