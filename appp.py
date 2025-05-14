from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb
import secrets
import os
from datetime import datetime, timedelta
import random
from flask_socketio import SocketIO
from flask_mail import Mail, Message
import re
import logging
import sys
import requests
import json
import traceback

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the parent directory to the path so we can import the ML model
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
POSSIBLE_MODEL_DIRS = [
    os.path.join(CURRENT_DIR, 'LindaMamaMLmodel'),  # If model is in app dir
    os.path.join(PARENT_DIR, 'LindaMamaMLmodel'),   # If model is in parent dir
    'LindaMamaMLmodel'                             # Relative to current dir
]

# Try to find the model directory
MODEL_DIR = None
for dir_path in POSSIBLE_MODEL_DIRS:
    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        MODEL_DIR = dir_path
        break

if MODEL_DIR:
    logger.info(f"✅ Found ML model directory at: {MODEL_DIR}")
    if MODEL_DIR not in sys.path:
        sys.path.insert(0, MODEL_DIR)
else:
    logger.error("❌ Could not find ML model directory. Checked paths:")
    for path in POSSIBLE_MODEL_DIRS:
        logger.error(f"  - {path}")

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:EddieOliver..1@localhost/linda_mama'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Flask-Mail for actual email sending
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'oliedd003@gmail.com'
app.config['MAIL_PASSWORD'] = 'izstwblikkwnegfl'  # App password from Google
app.config['MAIL_DEFAULT_SENDER'] = 'oliedd003@gmail.com'
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False  # Enable actual email sending
app.config['MAIL_MAX_EMAILS'] = 5
app.config['TESTING'] = False
mail = Mail(app)

# Make datetime available in all templates
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# ---------------------------------------------------
# 1) Configure SQLAlchemy (ORM) and MySQL (raw SQL)
# ---------------------------------------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'EddieOliver..1'
app.config['MYSQL_DB'] = 'linda_mama'
mysql = MySQL(app)

# ---------------------------------------------------
# 2) Configure Google OAuth
# ---------------------------------------------------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="944644137951-fktmua0vvs3d4imfh2nl5iirv7uhft5d.apps.googleusercontent.com",
    client_secret="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",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    redirect_uri="http://127.0.0.1:5000/google/callback",
    client_kwargs={"scope": "openid email profile"}
)

# ---------------------------------------------------
# 3) SQLAlchemy Models
# ---------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)  
    role = db.Column(db.String(20), nullable=False)  # 'mother', 'guardian', 'doctor'
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    
    # Relationships
    mother_profile = db.relationship('MotherProfile', backref='user', uselist=False)
    doctor_profile = db.relationship('DoctorProfile', backref='user', uselist=False)
    guardian_requests = db.relationship('GuardianRequest', backref='guardian', foreign_keys='GuardianRequest.guardian_id')
    guardian_approvals = db.relationship('GuardianApproval', backref='guardian', foreign_keys='GuardianApproval.guardian_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class GuardianRequest(db.Model):
    __tablename__ = "guardian_requests"
    id = db.Column(db.Integer, primary_key=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mother_email = db.Column(db.String(100), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected

class GuardianApproval(db.Model):
    __tablename__ = "guardian_approvals"
    id = db.Column(db.Integer, primary_key=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mother_id = db.Column(db.Integer, db.ForeignKey('mother_profiles.user_id'), nullable=False)
    approval_date = db.Column(db.DateTime, default=datetime.utcnow)

class HealthMetric(db.Model):
    __tablename__ = "health_metrics"
    id = db.Column(db.Integer, primary_key=True)
    mother_id = db.Column(db.Integer, db.ForeignKey('mother_profiles.user_id'), nullable=False)
    date_recorded = db.Column(db.DateTime, default=datetime.utcnow)
    weight = db.Column(db.Float)
    blood_pressure = db.Column(db.String(20))
    heart_rate = db.Column(db.Integer)
    blood_sugar = db.Column(db.Float)
    body_temperature = db.Column(db.Float)

class Appointment(db.Model):
    __tablename__ = "appointments"
    id = db.Column(db.Integer, primary_key=True)
    mother_id = db.Column(db.Integer, db.ForeignKey('mother_profiles.user_id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor_profiles.user_id'), nullable=True)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    appointment_type = db.Column(db.String(50))
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled

class ForumCategory(db.Model):
    __tablename__ = "forum_categories"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    posts = db.relationship('ForumPost', backref='category', lazy=True)

class ForumPost(db.Model):
    __tablename__ = "forum_posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('forum_categories.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('ForumComment', backref='post', lazy=True)

class ForumComment(db.Model):
    __tablename__ = "forum_comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    comment_date = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    message_type = db.Column(db.String(20), default='user')  # user, doctor, ai

class MotherProfile(db.Model):
    __tablename__ = "mother_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    current_week = db.Column(db.Integer, nullable=True)
    trimester = db.Column(db.String(20), nullable=True)
    weight = db.Column(db.Float)
    blood_pressure = db.Column(db.String(20))
    sugar_levels = db.Column(db.Float)
    age = db.Column(db.String(20))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor_profiles.id'), nullable=True)
    last_visit_date = db.Column(db.DateTime, nullable=True)
    height = db.Column(db.Float)
    bmi = db.Column(db.Float)
    
    # Guardian approvals - mothers who approved this guardian
    approvals_received = db.relationship('GuardianApproval', backref='mother', foreign_keys='GuardianApproval.mother_id')
    # Health metrics
    health_metrics = db.relationship('HealthMetric', backref='mother', lazy=True)
    # Appointments
    appointments = db.relationship('Appointment', backref='mother', lazy=True)
    # Risk predictions
    risk_predictions = db.relationship('RiskPrediction', backref='mother', lazy=True)

class DoctorProfile(db.Model):
    __tablename__ = "doctor_profiles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    specialty = db.Column(db.String(100))
    hospital = db.Column(db.String(150))
    
    # Appointments scheduled with this doctor
    appointments = db.relationship('Appointment', backref='doctor', lazy=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50))
    related_id = db.Column(db.Integer)  # ID of related record (e.g., guardian request)

class RiskPrediction(db.Model):
    __tablename__ = "risk_predictions"
    id = db.Column(db.Integer, primary_key=True)
    mother_id = db.Column(db.Integer, db.ForeignKey('mother_profiles.user_id'), nullable=False)
    date_predicted = db.Column(db.DateTime, default=datetime.utcnow)
    risk_level = db.Column(db.String(20))  # Low, Medium, High
    top_factors = db.Column(db.Text)  # JSON string of top factors
    recommendation = db.Column(db.Text)
    input_data = db.Column(db.Text)  # JSON string of input data
    
    # Remove the conflicting relationship - MotherProfile already has this defined
    # mother = db.relationship('MotherProfile', backref='risk_predictions')

# ---------------------------------------------------
# 4) Routes
# ---------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        role = request.form.get('role')
        mother_email = request.form.get('mother_email') # Get mother_email (might be None if role is not guardian)

        # --- Existing checks (email exists, domain, password complexity) ---
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Account already exists. Please login instead.')
            return redirect(url_for('login'))

        if not (email.endswith('@gmail.com') or email.endswith('@yahoo.com')):
             flash('Email must be a Gmail or Yahoo address.')
             return redirect(url_for('signup'))

        password_regex = re.compile(r'^(?=.*\d)(?=.*[!@#$%^&*\.])[a-zA-Z0-9!@#$%^&*\.]{6,}$')
        if not password_regex.match(password):
            flash('Password must be at least 6 characters long and include at least 1 number and 1 symbol.')
            return redirect(url_for('signup'))
        # --- End of existing checks ---

        # --- Check if mother_email is provided for guardian role ---
        if role == 'guardian' and not mother_email:
            flash('Mother\'s email is required when signing up as a guardian.')
            return redirect(url_for('signup'))
        # --- End check ---

        verification_token = secrets.token_urlsafe(32)
        username = email # Use email as username

        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            verification_token=verification_token
        )
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.flush() # Flush to get the new_user.id

            assigned_doctor_profile_id = None # Keep track of assigned doctor

            # --- Doctor Assignment Logic (if role is 'mother') ---
            if role == 'mother':
                # Find available doctors
                available_doctors = DoctorProfile.query.all()

                # Create the MotherProfile
                mother_profile = MotherProfile(user_id=new_user.id)
                
                # Only assign a doctor if doctors exist
                if available_doctors:
                    # Simple random assignment if doctors exist
                    chosen_doctor_profile = random.choice(available_doctors)
                    mother_profile.doctor_id = chosen_doctor_profile.id # Assign the DoctorProfile ID
                    print(f"Assigning mother {new_user.email} to doctor profile ID {chosen_doctor_profile.id}")
                else:
                    # Create profile without a doctor
                    print(f"No doctors available to assign to mother {new_user.email}")
                
                db.session.add(mother_profile)

            # --- Handle Doctor Profile Creation (if role is 'doctor') ---
            elif role == 'doctor':
                 # (Keep your existing doctor profile creation logic here)
                 # ... (rest of your doctor logic) ...
                 doctor_profile = DoctorProfile(
                     user_id=new_user.id,
                     specialty="General Practice", # Example default
                     hospital="Community Hospital" # Example default
                 )
                 db.session.add(doctor_profile)


            # --- Handle Guardian Request (if role is 'guardian') ---
            elif role == 'guardian':
                # Step 1: Create the GuardianRequest
                print(f"Creating GuardianRequest for guardian ID {new_user.id} and mother email {mother_email}") # Debug
                guardian_request = GuardianRequest(
                    guardian_id=new_user.id,       # ID of the user being created
                    mother_email=mother_email    # Email provided in the form
                )
                db.session.add(guardian_request)
                # Flush again to get the ID of the guardian_request for the notification
                db.session.flush()
                print(f"GuardianRequest object added, attempting flush. Request ID (after flush): {guardian_request.id}") # Debug

                # Step 2: Find the Mother User
                print(f"Searching for mother with email: {mother_email}") # Debug
                mother = User.query.filter_by(email=mother_email, role='mother').first()

                # Step 3: Create Notification for the Mother (if found)
                if mother:
                    print(f"Mother found (ID: {mother.id}). Creating notification.") # Debug
                    notification = Notification(
                        user_id=mother.id,            # The mother's user ID
                        content=f"{new_user.full_name} wants to be your guardian.",
                        notification_type="guardian_request",
                        related_id=guardian_request.id # Link to the request record
                    )
                    db.session.add(notification)
                    print(f"Notification object added for mother ID {mother.id}") # Debug
                else:
                    # Optional: Log or handle the case where the mother's email doesn't exist
                    print(f"Warning: Mother with email {mother_email} not found. Guardian request created, but no notification sent.")
                    # You might want to flash a different message to the guardian here
                    # flash('Guardian request created, but the mother\'s email was not found in our system.')
            # --- END: ADD THIS BLOCK ---


            # Commit all changes (user, profile, request, notification, etc.)
            db.session.commit() # This single commit saves everything added to the session

            # --- Email Verification Logic ---
            # (Keep your existing email verification logic here)
            # ... (rest of email logic) ...
            verification_url = url_for('verify_email', token=verification_token, _external=True)
            try:
                email_sent = send_verification_email(new_user)
                if email_sent:
                    flash(f'Account created! Please check your email to verify your account. You must verify your email before logging in.')
                else:
                    # Provide fallback link if email fails
                    flash(f'Email could not be sent. Please click this link to verify your account: <a href="{verification_url}" class="verification-link">Verify Account</a>', 'verification')
            except Exception as e:
                print(f"Error in signup sending email: {str(e)}")
                # Provide fallback link on exception
                flash(f'Account created! Click this link to verify your account: <a href="{verification_url}" class="verification-link">Verify Account</a>', 'verification')


            # For guardians, redirect to login but maybe show a specific message
            if role == 'guardian':
                 flash('Account created! Please verify your email. Your request to be a guardian has been sent to the mother for approval.')
                 return redirect(url_for('login'))
            else:
                 # Standard redirect for mother/doctor after verification email info
                 return redirect(url_for('login'))


        except Exception as e:
            db.session.rollback() # Rollback in case of any error during the process
            print(f"Error during signup or related record creation: {str(e)}")
            import traceback
            traceback.print_exc() # Print detailed error traceback to console
            flash('An error occurred during signup. Please try again.')
            return redirect(url_for('signup'))

    # If GET request or failed POST
    return render_template('signup.html')

def send_verification_email(user):
    """
    Send a verification email to a newly registered user.
    Returns True if email was sent successfully, False otherwise.
    """
    token = user.verification_token
    verification_url = url_for('verify_email', token=token, _external=True)

    try:
        # Create the message
        msg = Message(
            subject='Verify your email for Linda Mama Health System',
            recipients=[user.email]
        )
        
        # Set text body
        msg.body = f'''Hello {user.full_name},

Please verify your email by clicking on the following link: {verification_url}

Thank you,
Linda Mama Health System Team'''

        # Set HTML body
        msg.html = f'''
        <h1>Welcome to Linda Mama Health System!</h1>
        <p>Hello {user.full_name},</p>
        <p>Please verify your email by clicking on the following link:</p>
        <p><a href="{verification_url}">Verify Your Email</a></p>
        <p>Or copy and paste this URL into your browser:</p>
        <p>{verification_url}</p>
        <p>Thank you,<br>Linda Mama Health System Team</p>
        '''
        
        # Print diagnostic information
        print(f"Attempting to send email to: {user.email}")
        print(f"Verification URL: {verification_url}")
        
        # Send the email
        mail.send(msg)
        
        print(f"Email sent successfully to {user.email}")
        return True
        
    except Exception as e:
        print(f"Failed to send email to {user.email}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Your account has been verified! You can now login.')
    else:
        flash('Invalid or expired verification link.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with that email address.', 'login_error')
            return redirect(url_for('login'))
            
        if not user.check_password(password):
            flash('Invalid password. Please try again.', 'login_error')
            return redirect(url_for('login'))
            
        if not user.is_verified:
            flash('Please verify your email before logging in.', 'login_error')
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for(f'{user.role}_dashboard'))
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

@app.route('/mother_dashboard')
@login_required
def mother_dashboard():
    if current_user.role != 'mother':
        return redirect(url_for('login'))

    mother_profile = MotherProfile.query.filter_by(user_id=current_user.id).first()

    if not mother_profile:
        mother_profile = MotherProfile(user_id=current_user.id)
        db.session.add(mother_profile)
        db.session.commit()
        flash("Welcome! Your profile has been created.")

    # --- Fetch Assigned Doctor Details ---
    doctor_details = None
    if mother_profile.doctor_id:
        # Join DoctorProfile with User table to get the doctor's name
        doctor_info = db.session.query(DoctorProfile, User)\
            .join(User, User.id == DoctorProfile.user_id)\
            .filter(DoctorProfile.id == mother_profile.doctor_id)\
            .first()
        if doctor_info:
            doctor_profile, doctor_user = doctor_info
            doctor_details = {
                'full_name': doctor_user.full_name,
                'specialty': doctor_profile.specialty,
                 'hospital': doctor_profile.hospital
                # Add other details if needed
            }
    # --- End Fetch Doctor Details ---

    latest_metrics = HealthMetric.query.filter_by(mother_id=current_user.id).order_by(HealthMetric.date_recorded.desc()).first()

    # --- Fetch Actual Upcoming Appointments ---
    # Query appointments specifically for this mother
    upcoming_appointments = Appointment.query.filter(
        Appointment.mother_id == current_user.id, # Filter by mother's user_id
        Appointment.status == 'scheduled',
        Appointment.date >= datetime.utcnow().date() # Show only today or future appointments
    ).order_by(Appointment.date, Appointment.time).limit(5).all() # Limit to 5 for the dashboard
    # --- End Fetch Appointments ---


    guardian_requests_query = GuardianRequest.query.filter_by(
        mother_email=current_user.email,
        status='pending'
    ).all()

    guardian_requests = []
    for request in guardian_requests_query:
        guardian = User.query.get(request.guardian_id)
        guardian_requests.append({
            'id': request.id,
            'guardian_id': request.guardian_id,
            'guardian_name': guardian.full_name if guardian else 'Unknown',
            'request_date': request.request_date.strftime('%Y-%m-%d')
        })

    return render_template(
        'mother/mother_dashboard.html', # Ensure this path is correct
        mother_profile=mother_profile,
        metrics=latest_metrics,
        appointments=upcoming_appointments, # Pass the actual appointments
        doctor_details=doctor_details, # Pass the doctor details
        guardian_requests=guardian_requests
    )

@app.route("/google_login")
def google_login():
    # Set up nonce for security
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce
    
    # Redirect to Google authentication
    return google.authorize_redirect(
        url_for("google_callback", _external=True),
        nonce=nonce,
        prompt="consent"  # Always show consent screen
    )

@app.route("/google_callback")
def google_callback():
    token = google.authorize_access_token()
    if token is None:
        flash("Google login failed!", "danger")
        return redirect(url_for("login"))

    nonce = session.pop("nonce", None)
    if nonce is None:
        flash("Login failed: missing nonce", "danger")
        return redirect(url_for("login"))

    user_info = google.parse_id_token(token, nonce)
    email = user_info["email"]
    full_name = user_info.get("name", "Google User")

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    
    if existing_user:
        # User exists - log them in
        login_user(existing_user)
        
        # Check if guardian has approval
        if existing_user.role == "guardian":
            approval = GuardianApproval.query.filter_by(guardian_id=existing_user.id).first()
            if not approval:
                flash("Your guardian request is still pending approval")
                return redirect(url_for("login"))
                
        flash("Login successful!", "success")
        return redirect(url_for(f"{existing_user.role}_dashboard"))
    else:
        # New user - get role from session
        role = session.pop("google_signup_role", None)
        
        if not role:
            flash("Please select a role before signing up with Google")
            return redirect(url_for("signup_with_google"))
        
        # Create the new user with the selected role
        new_user = User(
            username=email,
            email=email,
            full_name=full_name,
            role=role
        )
        new_user.set_password(secrets.token_urlsafe(16))  # Random secure password
        db.session.add(new_user)
        db.session.commit()
        
        # Handle role-specific setup
        if role == "mother":
            mother_profile = MotherProfile(user_id=new_user.id)
            db.session.add(mother_profile)
            
        elif role == "doctor":
            specialty = session.pop("doctor_specialty", "")
            hospital = session.pop("doctor_hospital", "")
            doctor_profile = DoctorProfile(
                user_id=new_user.id,
                specialty=specialty,
                hospital=hospital
            )
            db.session.add(doctor_profile)
            
        elif role == "guardian":
            mother_email = session.pop("guardian_mother_email", "")
            guardian_request = GuardianRequest(
                guardian_id=new_user.id,
                mother_email=mother_email
            )
            db.session.add(guardian_request)
            
            # Create notification for mother
            mother = User.query.filter_by(email=mother_email, role="mother").first()
            if mother:
                notification = Notification(
                    user_id=mother.id,
                    content=f"{full_name} wants to be your guardian",
                    notification_type="guardian_request",
                    related_id=guardian_request.id
                )
                db.session.add(notification)
        
        db.session.commit()
        
        # Log in the new user
        login_user(new_user)
        
        # For guardians, show waiting page
        if role == "guardian":
            flash("Your guardian request has been sent. Please wait for approval.")
            return render_template('login.html')
            
        flash("Sign up successful!", "success")
        return redirect(url_for(f"{role}_dashboard"))

@app.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        return redirect(url_for('login'))
    
    # Ensure doctor profile exists
    if not hasattr(current_user, 'doctor_profile') or not current_user.doctor_profile:
        doctor_profile = DoctorProfile(user_id=current_user.id)
        db.session.add(doctor_profile)
        db.session.commit()
        current_user.doctor_profile = doctor_profile

    # Fetch patients assigned to the doctor, joining with User to get full name
    patients = db.session.query(MotherProfile, User).join(
        User, User.id == MotherProfile.user_id
    ).filter(MotherProfile.doctor_id == current_user.doctor_profile.id).all()
    
    # Create a separate list of patient-user mappings for JavaScript
    patient_user_map = []
    for patient, user in patients:
        patient_user_map.append({
            'patient_id': patient.id,
            'user_id': user.id,
            'name': user.full_name
        })
    
    # Fetch the doctor's upcoming appointments
    upcoming_appointments = db.session.query(
        Appointment, User, MotherProfile
    ).join(
        MotherProfile, Appointment.mother_id == MotherProfile.user_id
    ).join(
        User, User.id == MotherProfile.user_id
    ).filter(
        Appointment.doctor_id == current_user.id,
        Appointment.status == 'scheduled'
    ).order_by(
        Appointment.date, Appointment.time
    ).all()
    
    # Format the appointments for the template
    formatted_appointments = []
    for appt, user, profile in upcoming_appointments:
        formatted_appointments.append({
            'id': appt.id,
            'date': appt.date,
            'time': appt.time,
            'patient_name': user.full_name,
            'patient_id': profile.id,
            'appointment_type': appt.appointment_type
        })

    return render_template(
        'doctor/doctor_dashboard.html', 
        doctor_name=current_user.full_name, 
        patients=patients,
        patient_user_map=patient_user_map,
        appointments=formatted_appointments
    )

@app.route('/guardian_dashboard')
@login_required
def guardian_dashboard():
    if current_user.role != 'guardian':
        return redirect(url_for('login'))

    # Get the mother this guardian is approved for
    approval = GuardianApproval.query.filter_by(guardian_id=current_user.id).first()
    
    if not approval:
        return "Your guardian request is still pending approval"
    
    mother = User.query.get(approval.mother_id)
    mother_profile = MotherProfile.query.filter_by(user_id=mother.id).first()
    
    # Get mother's latest health metrics
    latest_metrics = HealthMetric.query.filter_by(mother_id=mother.id).order_by(HealthMetric.date_recorded.desc()).first()
    
    # Get mother's upcoming appointments
    appointments = Appointment.query.filter_by(
        mother_id=mother.id, 
        status='scheduled'
    ).order_by(Appointment.date).limit(1).all()
    
    return render_template(
        'guardian/guardian_dashboard.html',
        mother=mother,
        mother_profile=mother_profile,
        metrics=latest_metrics,
        appointments=appointments,
        now=datetime.utcnow
    )

@app.route('/approve_guardian/<int:request_id>/<action>')
@login_required
def approve_guardian(request_id, action):
    if current_user.role != 'mother':
        flash('Permission denied')
        return redirect(url_for('mother_dashboard'))
    
    guardian_request = GuardianRequest.query.get_or_404(request_id)
    
    if guardian_request.mother_email != current_user.email:
        flash('Permission denied')
        return redirect(url_for('mother_dashboard'))
    
    if action == 'approve':
        # Create approval record
        approval = GuardianApproval(
            guardian_id=guardian_request.guardian_id,
            mother_id=current_user.id
        )
        db.session.add(approval)
        guardian_request.status = 'approved'
        db.session.commit()
        
        # Determine if it's an AJAX request
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({"success": True, "message": "Guardian approved"})
        else:
            flash('Guardian approved')
            return redirect(url_for('mother_dashboard'))
    
    elif action == 'deny':
        guardian_request.status = 'rejected'
        db.session.commit()
        
        # Determine if it's an AJAX request
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({"success": True, "message": "Guardian request denied"})
        else:
            flash('Guardian request denied')
            return redirect(url_for('mother_dashboard'))
    
    # If we get here, it's an invalid action
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({"success": False, "message": "Invalid action"}), 400
    else:
        flash('Invalid action')
        return redirect(url_for('mother_dashboard'))

@app.route('/deny_guardian/<int:request_id>', methods=['POST'])
def deny_guardian(request_id):
    try:
        request_entry = GuardianRequest.query.get(request_id)
        if not request_entry:
            return jsonify({"error": "Request not found"}), 404

        db.session.delete(request_entry)
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("Deny guardian error:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/get_guardian_requests', methods=['GET'])
def get_guardian_requests():
    if 'user_id' not in session or session['role'] != 'mother':
        return {"success": False, "message": "Unauthorized access!"}, 403

    mother_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, guardian_email, guardian_name
        FROM guardian_requests
        WHERE mother_id = %s AND status = 'pending'
    """, (mother_id,))
    guardian_requests = cursor.fetchall()
    cursor.close()

    requests_list = [{"id": req[0], "guardian_email": req[1], "guardian_name": req[2]} for req in guardian_requests]
    return {"success": True, "guardian_requests": requests_list}

@app.route('/submit_health_metrics', methods=['POST'])
@login_required
def submit_health_metrics():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        current_week = int(data.get('current_week'))
        height = float(data.get('height'))  # Get height
        weight = float(data.get('weight'))  # Get weight
        bmi = float(data.get('bmi'))  # Get BMI
        due_date = datetime.now() + timedelta(weeks=(40 - current_week))  # Calculate due date
        formatted_due_date = due_date.date()  # Format for storage

        # Check if a MotherProfile already exists for the current user
        mother_profile = MotherProfile.query.filter_by(user_id=current_user.id).first()

        if mother_profile:
            # Update the existing profile
            mother_profile.weight = weight
            mother_profile.height = height  # Update height
            mother_profile.bmi = bmi  # Update BMI
            mother_profile.blood_pressure = data.get('blood_pressure')
            mother_profile.sugar_levels = data.get('blood_sugar')
            mother_profile.age = data.get('age')
            mother_profile.current_week = current_week
            mother_profile.trimester = data.get('trimester')
            mother_profile.due_date = formatted_due_date
        else:
            # Create a new MotherProfile instance if it doesn't exist
            mother_profile = MotherProfile(
                user_id=current_user.id,
                weight=weight,
                height=height,  # Store height
                bmi=bmi,  # Store BMI
                blood_pressure=data.get('blood_pressure'),
                sugar_levels=data.get('blood_sugar'),
                age=data.get('age'),
                current_week=current_week,
                trimester=data.get('trimester'),
                due_date=formatted_due_date
            )
            db.session.add(mother_profile)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({"success": True, "metrics": data})
    except Exception as e:
        print("Error saving health metrics:", e)
        return jsonify({"success": False, "error": str(e)}), 500

# Move these lines near line 35, right after db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Fetch latest health metrics as JSON (for AJAX updates)
@app.route('/api/health_metrics/latest')
@login_required
def get_latest_metrics():
    mother_id = current_user.id
    
    # For guardians, get the associated mother's ID
    if current_user.role == 'guardian':
        approval = GuardianApproval.query.filter_by(guardian_id=current_user.id).first()
        if not approval:
            return {"error": "No approved mother found"}, 403
        mother_id = approval.mother_id
    
    # Get latest metrics
    latest = HealthMetric.query.filter_by(mother_id=mother_id).order_by(HealthMetric.date_recorded.desc()).first()
    
    if latest:
        return {
            "weight": latest.weight,
            "blood_pressure": latest.blood_pressure,
            "heart_rate": latest.heart_rate,
            "blood_sugar": latest.blood_sugar,
            "body_temperature": latest.body_temperature,
            "date_recorded": latest.date_recorded.strftime('%Y-%m-%d %H:%M:%S')
        }
    else:
        return {"error": "No health metrics found"}, 404

# Forum post creation
@app.route('/api/forum/post', methods=['POST'])
@login_required
def create_forum_post():
    data = request.json
    
    new_post = ForumPost(
        user_id=current_user.id,
        category_id=data.get('category_id'),
        title=data.get('title'),
        content=data.get('content')
    )
    
    db.session.add(new_post)
    db.session.commit()
    
    return {"success": True, "post_id": new_post.id}

# Message sending API (for doctor chat and AI assistant)
@app.route('/api/messages/send', methods=['POST'])
@login_required
def send_message():
    data = request.json
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    message_type = data.get('message_type', 'user')  # Default to 'user'
    
    # Special handling for doctor-patient communication
    if current_user.role == 'doctor':
        # Check if receiver_id might be a mother's profile ID instead of User.id
        # First try to see if it's a valid user ID
        receiver_user = User.query.get(receiver_id)
        if not receiver_user:
            # It might be a mother profile ID, try to get the associated user
            mother_profile = MotherProfile.query.get(receiver_id)
            if mother_profile:
                receiver_id = mother_profile.user_id
    
    # Special handling for mother-doctor communication
    elif current_user.role == 'mother':
        # If receiver_id is a DoctorProfile ID, convert to User.id
        receiver_user = User.query.get(receiver_id)
        if not receiver_user:
            # It might be a doctor profile ID
            doctor_profile = DoctorProfile.query.get(receiver_id)
            if doctor_profile:
                receiver_id = doctor_profile.user_id
    
    # Final validation of receiver ID
    if not receiver_id or not User.query.get(receiver_id):
        return {"success": False, "error": "Invalid receiver ID"}, 400

    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content,
        message_type=message_type
    )

    db.session.add(new_message)
    db.session.commit()

    return {"success": True, "message_id": new_message.id}

# Get conversation history
@app.route('/api/messages/conversation/<int:other_user_id>')
@login_required
def get_conversation(other_user_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    conversation = []
    for msg in messages:
        conversation.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "content": msg.content,
            "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "is_sender": msg.sender_id == current_user.id
        })
    
    return {"conversation": conversation}

# Route to fetch notifications
@app.route('/api/notifications')
@login_required
def get_notifications():
    print(f"Fetching notifications for user ID: {current_user.id}")
    
    try:
        notifications = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).order_by(Notification.timestamp.desc()).all()
        
        print(f"Found {len(notifications)} notifications")
        
        result = []
        for notif in notifications:
            result.append({
                "id": notif.id,
                "content": notif.content,
                "timestamp": notif.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "type": notif.notification_type,
                "related_id": notif.related_id
            })
        
        # Also check for guardian requests
        guardian_requests = GuardianRequest.query.filter_by(
            mother_email=current_user.email,
            status='pending'
        ).all()
        
        print(f"Found {len(guardian_requests)} guardian requests")
        
        # Convert guardian requests to notifications format
        guardian_request_notifications = []
        for request in guardian_requests:
            guardian = User.query.get(request.guardian_id)
            if guardian:
                guardian_request_notifications.append({
                    "id": request.id,
                    "content": f"{guardian.full_name} wants to be your guardian",
                    "timestamp": request.request_date.strftime('%Y-%m-%d %H:%M:%S'),
                    "type": "guardian_request",
                    "related_id": request.id,
                    "guardian_id": request.guardian_id,
                    "guardian_name": guardian.full_name,
                    "request_date": request.request_date.strftime('%Y-%m-%d')
                })
        
        # Add guardian requests to notifications
        result.extend(guardian_request_notifications)
        
        # Return response with debug info
        response = {
            "notifications": result,
            "guardian_requests": guardian_request_notifications,  # Add the guardian requests separately
            "debug_info": {
                "user_id": current_user.id,
                "user_email": current_user.email,
                "user_role": current_user.role,
                "notification_count": len(notifications),
                "guardian_request_count": len(guardian_requests)
            }
        }
        
        return response
    except Exception as e:
        print(f"Error in get_notifications: {str(e)}")
        return {"notifications": [], "guardian_requests": [], "error": str(e)}

# Mark notification as read
@app.route('/api/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return {"error": "Permission denied"}, 403
    
    notification.is_read = True
    db.session.commit()
    
    return {"success": True}

@app.route('/settings.html')
@login_required
def settings():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    return render_template('mother/settings.html')

@app.route('/health_monitoring.html')
@login_required
def health_monitoring():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    
    # Get the mother profile for the current user
    mother_profile = MotherProfile.query.filter_by(user_id=current_user.id).first()
    
    # If no profile exists, create one
    if not mother_profile:
        mother_profile = MotherProfile(user_id=current_user.id)
        db.session.add(mother_profile)
        db.session.commit()
    
    return render_template('mother/health_monitoring.html', mother_profile=mother_profile)

@app.route('/mealplan_and_nutrition.html')
@login_required
def mealplan_and_nutrition():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    # Pass empty guardian_requests to avoid the error
    return render_template('mother/mealplan_and_nutrition.html', guardian_requests=[])

@app.route('/comm_and_support.html')
@login_required
def comm_and_support():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    return render_template('mother/comm_and_support.html')

@app.route('/general.html')
@login_required
def general_chat():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    return render_template('mother/general.html')

@app.route('/pregnancy_experience.html')
@login_required
def pregnancy_experience_chat():
    if current_user.role != 'mother':
        return redirect(url_for('login'))
    return render_template('mother/pregnancy_experience.html')

@app.route("/signup_with_google", methods=["GET", "POST"])
def signup_with_google():
    if request.method == "POST":
        role = request.form.get("role")
        
        # Validate the role
        if role not in ["mother", "doctor", "guardian"]:
            flash("Invalid role selected")
            return redirect(url_for("signup_with_google"))
        
        # Store the selected role in session
        session["google_signup_role"] = role
        
        # If guardian, collect mother's email
        if role == "guardian":
            mother_email = request.form.get("mother_email")
            if not mother_email:
                flash("Mother's email is required for guardian signup")
                return redirect(url_for("signup_with_google"))
            session["guardian_mother_email"] = mother_email
        
        # If doctor, collect specialty and hospital
        if role == "doctor":
            specialty = request.form.get("specialty")
            hospital = request.form.get("hospital")
            if not specialty or not hospital:
                flash("Specialty and hospital are required for doctor signup")
                return redirect(url_for("signup_with_google"))
            session["doctor_specialty"] = specialty
            session["doctor_hospital"] = hospital
        
        # Now redirect to Google OAuth
        return redirect(url_for("google_login"))
        
    return render_template("signup_with_google.html")

def setup_doctor_mother_relationship():
    """
    Function to link mother profiles to existing doctors.
    Does not create any new doctor accounts or profiles.
    """
    # Get all available doctor profiles
    doctor_profiles = DoctorProfile.query.all()
    print(f"Found {len(doctor_profiles)} existing doctor profiles for assignment")
    
    # If no doctors exist, don't do anything
    if not doctor_profiles:
        print("No doctor profiles found in the database. Please create doctors before assigning mothers.")
        return None
    
    # Get all mother profiles
    all_mother_profiles = MotherProfile.query.all()
    print(f"Found {len(all_mother_profiles)} total mothers in system")
    
    # Assign ALL mothers to doctors
    assigned_count = 0
    for mother_profile in all_mother_profiles:
        chosen_doctor = doctor_profiles[0] if len(doctor_profiles) == 1 else random.choice(doctor_profiles)
        mother_profile.doctor_id = chosen_doctor.id
        print(f"Assigned mother ID {mother_profile.id} (user_id: {mother_profile.user_id}) to doctor profile ID {chosen_doctor.id}")
        assigned_count += 1
    
    print(f"Total mothers assigned: {assigned_count}")
    db.session.commit()
    
    # Return the first doctor profile ID for reference
    return doctor_profiles[0].id if doctor_profiles else None

# For development purposes - initialize at startup
# Uncomment this if you want to automatically setup the relationship when the app starts
@app.route('/setup_doctor')
def init_app_data():
    """Development endpoint to set up doctor and mother relationship"""
    doctor_profile_id = setup_doctor_mother_relationship()
    return f"Doctor setup complete. Doctor profile ID: {doctor_profile_id}"

@app.route('/predict_risk', methods=['POST'])
@login_required
def predict_risk_route():
    """Handle risk prediction requests from the health monitoring page"""
    if not request.is_json:
        # Handle form data if it's not JSON
        try:
            # Extract form data
            input_data = {
                'age': request.form.get('age', '0'),
                'blood_pressure': request.form.get('blood_pressure', '0'),
                'heart_rate': request.form.get('heart_rate', '0'),
                'blood_sugar': request.form.get('blood_sugar', '0'),
                'haemoglobin': request.form.get('haemoglobin', '0'),
                'weight': request.form.get('weight', '0'),
                'height': request.form.get('height', '0'),
                'gestational_week': request.form.get('gestational_week', '0'),
                'prenatal_visits': request.form.get('prenatal_visits', '0'),
                'miscarriage_history': request.form.get('miscarriage_history', 'No'),
                'smoking_alcohol': request.form.get('smoking_alcohol', 'No')
            }
            
            # Calculate BMI from weight and height
            weight = float(input_data['weight']) if input_data['weight'] else 0
            height = float(input_data['height']) if input_data['height'] else 0
            bmi = 0
            if weight > 0 and height > 0:
                # Convert height from cm to meters
                height_in_meters = height / 100
                bmi = weight / (height_in_meters * height_in_meters)
                bmi = round(bmi, 2)
                
            # Add BMI to input data
            input_data['bmi'] = str(bmi)
            
            # Simple risk assessment logic
            # This is a placeholder - replace with actual ML model logic when available
            risk_points = 0
            
            # Convert values to float and handle potential conversion errors
            try:
                bp = float(input_data['blood_pressure'].split('/')[0]) if '/' in input_data['blood_pressure'] else float(input_data['blood_pressure']) if input_data['blood_pressure'] else 0
                hr = float(input_data['heart_rate']) if input_data['heart_rate'] else 0
                bs = float(input_data['blood_sugar']) if input_data['blood_sugar'] else 0
                hb = float(input_data['haemoglobin']) if input_data['haemoglobin'] else 0
                
                # Simple risk scoring
                if bp > 140: risk_points += 1
                if hr > 100: risk_points += 1
                if bs > 110: risk_points += 1
                if hb < 10: risk_points += 1
                if bmi > 30: risk_points += 1
                if input_data['miscarriage_history'] == 'Yes': risk_points += 1
                if input_data['smoking_alcohol'] == 'Yes': risk_points += 1
            except ValueError:
                # Handle conversion errors
                return jsonify({
                    "error": "Invalid input values. Please enter numeric values for measurements."
                }), 400
            
            # Determine risk level
            risk_level = "Low"
            if risk_points == 1 or risk_points == 2:
                risk_level = "Medium"
            elif risk_points >= 3:
                risk_level = "High"
                
            # Create recommendation based on risk level
            recommendation = "Continue with regular check-ups."
            if risk_level == "Medium":
                recommendation = "Consider more frequent monitoring and consult with your doctor."
            elif risk_level == "High":
                recommendation = "Please consult with your doctor as soon as possible."
            
            # Save the prediction result
            try:
                prediction = RiskPrediction(
                    mother_id=current_user.id,
                    risk_level=risk_level,
                    top_factors=json.dumps(["Blood Pressure", "Heart Rate", "Blood Sugar", "Haemoglobin", "BMI", "Pregnancy History", "Lifestyle Factors"]),
                    recommendation=recommendation,
                    input_data=json.dumps(input_data)
                )
                db.session.add(prediction)
                db.session.commit()
                print(f"Saved prediction result to database with ID: {prediction.id}")
            except Exception as e:
                print(f"Error saving prediction to database: {str(e)}")
                db.session.rollback()
                # Continue without failing the request
            
            # Return results
            return jsonify({
                "success": True,
                "risk_level": risk_level,
                "recommendation": recommendation,
                "top_factors": ["Blood Pressure", "Heart Rate", "Blood Sugar", "Haemoglobin", "BMI"] if risk_points > 0 else ["No significant risk factors identified"]
            })
            
        except Exception as e:
            print(f"Error processing risk prediction: {str(e)}")
            traceback.print_exc()
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    # Original JSON handling logic (keep this part)
    try:
        input_data = request.get_json()
        
        # Log the request for debugging
        print(f"Risk prediction request from user {current_user.id}")
        print(f"Risk prediction input data: {input_data}")
        
        # Simple placeholder response since ML model integration might not be working
        result = {
            "success": True,
            "risk_level": "Low",
            "recommendation": "Continue with regular check-ups and maintain a healthy lifestyle.",
            "top_factors": ["Regular Exercise", "Balanced Diet", "Adequate Rest"]
        }
        
        # Save the prediction result to the database
        try:
            prediction = RiskPrediction(
                mother_id=current_user.id,
                risk_level=result["risk_level"],
                top_factors=json.dumps(result["top_factors"]),
                recommendation=result["recommendation"],
                input_data=json.dumps(input_data)
            )
            db.session.add(prediction)
            db.session.commit()
            print(f"Saved prediction result to database with ID: {prediction.id}")
        except Exception as e:
            print(f"Error saving prediction to database: {str(e)}")
            db.session.rollback()
            # Continue without failing the request
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Unexpected error in predict_risk route: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/mother/doctor_info')
@login_required
def get_mother_doctor_info():
    """API endpoint to get the assigned doctor info for a mother"""
    if current_user.role != 'mother':
        return jsonify({"success": False, "error": "User is not a mother"}), 403
        
    try:
        # Get the mother profile with the doctor relationship
        mother_profile = MotherProfile.query.filter_by(user_id=current_user.id).first()
        
        if not mother_profile or not mother_profile.doctor_id:
            return jsonify({"success": False, "message": "No doctor assigned"})
            
        # Get the doctor's profile
        doctor_profile = DoctorProfile.query.get(mother_profile.doctor_id)
        
        if not doctor_profile:
            return jsonify({"success": False, "message": "Doctor profile not found"})
            
        # Get the doctor's user information
        doctor_user = User.query.get(doctor_profile.user_id)
        
        if not doctor_user:
            return jsonify({"success": False, "message": "Doctor user not found"})
            
        # Return doctor information
        return jsonify({
            "success": True,
            "doctor_id": doctor_user.id,
            "doctor_name": doctor_user.full_name,
            "doctor_specialty": doctor_profile.specialty,
            "doctor_hospital": doctor_profile.hospital
        })
        
    except Exception as e:
        print(f"Error getting doctor info: {str(e)}")
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route('/api/patient_info/<int:patient_id>')
@login_required
def get_patient_info(patient_id):
    """API endpoint to get patient (mother) information for a doctor"""
    if current_user.role != 'doctor':
        return jsonify({"success": False, "error": "Unauthorized access"}), 403
        
    try:
        # First try to find the mother profile directly by ID
        mother_profile = MotherProfile.query.filter_by(id=patient_id).first()
        
        # If not found, try to find by user_id
        if not mother_profile:
            mother_profile = MotherProfile.query.filter_by(user_id=patient_id).first()
            
        if not mother_profile:
            return jsonify({"success": False, "message": "Patient not found"}), 404
            
        # Get the mother user info
        mother_user = User.query.get(mother_profile.user_id)
        
        if not mother_user:
            return jsonify({"success": False, "message": "Patient user not found"}), 404
            
        # Get the latest health metrics
        latest_metrics = HealthMetric.query.filter_by(mother_id=mother_profile.user_id).order_by(HealthMetric.date_recorded.desc()).first()
        
        # Calculate weeks of pregnancy based on due date if available
        current_week = None
        if mother_profile.due_date:
            # Calculate current week based on due date (40 weeks total)
            today = datetime.now().date()
            days_until_due = (mother_profile.due_date - today).days
            if days_until_due > 0:
                current_week = 40 - (days_until_due // 7)
            else:
                current_week = 40  # Already due or overdue
        
        # Get upcoming appointments
        upcoming_appointments = Appointment.query.filter_by(
            mother_id=mother_profile.user_id,
            doctor_id=current_user.id
        ).filter(
            Appointment.date >= datetime.now().date()
        ).order_by(Appointment.date, Appointment.time).all()
        
        appointments_data = []
        for appointment in upcoming_appointments:
            appointments_data.append({
                "id": appointment.id,
                "date": appointment.date.strftime('%Y-%m-%d'),
                "time": appointment.time.strftime('%H:%M'),
                "type": appointment.appointment_type or "Check-up",
                "status": appointment.status
            })
        
        # Determine trimester
        trimester = mother_profile.trimester or None
        if current_week and not trimester:
            if current_week <= 13:
                trimester = "First Trimester"
            elif current_week <= 26:
                trimester = "Second Trimester"
            else:
                trimester = "Third Trimester"
        
        # Get baby size comparison
        baby_size = None
        if current_week:
            if current_week <= 8:
                baby_size = "Grape 🍇"
            elif current_week <= 12:
                baby_size = "Lime 🍋"
            elif current_week <= 16:
                baby_size = "Avocado 🥑"
            elif current_week <= 20:
                baby_size = "Banana 🍌"
            elif current_week <= 24:
                baby_size = "Mango 🥭"
            elif current_week <= 28:
                baby_size = "Eggplant 🍆"
            elif current_week <= 32:
                baby_size = "Pineapple 🍍"
            elif current_week <= 36:
                baby_size = "Honeydew 🍈"
            else:
                baby_size = "Watermelon 🍉"
        
        # Return all the patient info
        return jsonify({
            "success": True,
            "patient_info": {
                "user_id": mother_user.id,
                "full_name": mother_user.full_name,
                "email": mother_user.email,
                "current_week": mother_profile.current_week or current_week,
                "trimester": trimester,
                "due_date": mother_profile.due_date.strftime('%Y-%m-%d') if mother_profile.due_date else None,
                "baby_size": baby_size,
                "weight": mother_profile.weight,
                "height": mother_profile.height,
                "bmi": mother_profile.bmi,
                "blood_pressure": mother_profile.blood_pressure,
                "sugar_levels": mother_profile.sugar_levels,
                "last_visit_date": mother_profile.last_visit_date.strftime('%Y-%m-%d') if mother_profile.last_visit_date else None,
                "latest_metrics": {
                    "weight": latest_metrics.weight if latest_metrics else None,
                    "blood_pressure": latest_metrics.blood_pressure if latest_metrics else None,
                    "heart_rate": latest_metrics.heart_rate if latest_metrics else None,
                    "blood_sugar": latest_metrics.blood_sugar if latest_metrics else None,
                    "body_temperature": latest_metrics.body_temperature if latest_metrics else None,
                    "date_recorded": latest_metrics.date_recorded.strftime('%Y-%m-%d') if latest_metrics and latest_metrics.date_recorded else None
                },
                "upcoming_appointments": appointments_data
            }
        })
        
    except Exception as e:
        print(f"Error getting patient info: {str(e)}")
        return jsonify({"success": False, "error": "Server error"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
