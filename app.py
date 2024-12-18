from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from send_email import send_email
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
import sqlite3
from functools import wraps

import datetime
import matplotlib.pyplot as plt
import io
import base64

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Set your secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agile_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
serializer = URLSafeTimedSerializer(app.secret_key)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Database setup (SQLite)
DATABASE = 'projects.db'

# Function to get database connection 
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL;')  # Enable WAL mode
    return db
def table_exists(table_name):
    db = get_db()
    try:
        db.execute(f"SELECT 1 FROM {table_name} LIMIT 1;")
        return True
    except sqlite3.OperationalError:
        return False

# Close database connection when the app context ends
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_request
def set_user_role():
    # Default role to 'user' if not already set
    session['user_role'] = session.get('user_role', 'user')
    session['user_name'] = session.get('user_name', 'Guest')

# Models for SQLAlchemy
class User(db.Model):
    __tablename__ = 'users'
    UserID = db.Column(db.Integer, primary_key=True)
    UserName = db.Column(db.String(150), unique=True, nullable=False)
    Email = db.Column(db.String(150), unique=True, nullable=False)
    Password = db.Column(db.String(150), nullable=False)
    Role = db.Column(db.String(50), nullable=False)
    ApprovalStatus = db.Column(db.String(10), default='No')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('You need to log in first!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_name', None)
    session.pop('user_role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    try:
        user_id = session.get('user_id')  # Fetch user ID from session
        if not user_id:
            return redirect(url_for('login'))
        if request.method == 'POST':
            # Fetch form data
            new_email = request.form['email']
            new_password = request.form['password']
            updated_fields = []
            # Update email and password (if provided)
            if new_email:
                db.execute(
                    "UPDATE Users SET Email = ? WHERE UserID = ?",
                    (new_email, user_id)
                )
                session['user_email'] = new_email  # Update session
                updated_fields.append("Email")

            if new_password:
                db.execute(
                    "UPDATE Users SET Password = ? WHERE UserID = ?",
                    (new_password, user_id)
                )
                updated_fields.append("Password")

            if updated_fields:
                db.commit()
                flash(f"{', '.join(updated_fields)} updated successfully!", 'profile')
            else:
                flash("No changes were made.", 'profile')
        # Fetch user data for rendering the profile
        user_data = db.execute(
            "SELECT UserName, Email, Password FROM Users WHERE UserID = ?",
            (user_id,)
        ).fetchone()

        if not user_data:
            flash('User not found.', 'profile')
            return render_template('404.html'), 404

        user = {
            "name": user_data['UserName'],
            "email": user_data['Email'],
            "password": user_data['Password']
        }
        return render_template('profile.html', user=user)
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while updating the profile.', 'profile')
        return render_template('404.html'), 500

# Routes for handling requests
@app.route('/')
@login_required
def dashboard():
    db = get_db()
    user_role = session.get('user_role', 'user')
    user_name = session.get('user_name', 'Guest')

    total_projects = db.execute('SELECT COUNT(*) FROM ProjectInfo').fetchone()[0]
    active_projects = db.execute("SELECT COUNT(*) FROM ProjectInfo WHERE Status = 'Active'").fetchone()[0]
    on_hold_projects = db.execute("SELECT COUNT(*) FROM ProjectInfo WHERE Status = 'On Hold'").fetchone()[0]
    
    stats = {"total_projects": total_projects, "active_projects": active_projects, "on_hold_projects": on_hold_projects}
    # Fetch all projects with ProductOwner name using JOIN
    projects = db.execute(''' 
        SELECT p.ProjectID, p.ProjectName, p.StartDate, p.EndDate, p.RevisedEndDate, p.Status, po.Name
        FROM ProjectInfo p
        JOIN ProductOwner po ON p.ProductOwnerID = po.ProductOwnerID
    ''').fetchall()

    return render_template('dashboard.html', user_role=user_role, projects=projects, stats=stats)

@app.route('/project/<int:project_id>')
@login_required
def project_overview(project_id):
    db = get_db()
    # Fetch project details, including ProductOwnerID
    project = db.execute(''' 
        SELECT p.ProjectID, p.ProjectName, p.ProductOwnerID, po.Name AS ProductOwnerName
        FROM ProjectInfo p
        JOIN ProductOwner po ON p.ProductOwnerID = po.ProductOwnerID
        WHERE p.ProjectID = ?;
    ''', (project_id,)).fetchone()
    if project:
        # Fetch sprints for the project
        sprints = db.execute('SELECT s.*, SUM(us.StoryPoints) AS TotalStoryPoints FROM Sprints s JOIN UserStories us ON s.SprintID = us.SprintID WHERE s.ProjectID = ? GROUP BY s.SprintID;', (project_id,)).fetchall()
        
        # Fetch user stories with UserName from Users table
        user_stories = db.execute(''' 
            SELECT us.UserStory, us.Status, us.Assignee, us.SprintId, u.UserName, us.Moscow, us.StoryPoints
            FROM UserStories us
            LEFT JOIN Users u ON us.Assignee = u.UserID
            WHERE us.ProjectID = ?
        ''', (project_id,)).fetchall()
        product_owner = db.execute(''' 
            SELECT * FROM ProductOwner WHERE ProductOwnerID = ?;
        ''', (project[2],)).fetchone()
        users = db.execute('SELECT UserID, UserName FROM Users').fetchall()
        # Pass the ProductOwnerName along with other data
        return render_template('project_overview.html', product_owner=product_owner, project=project, sprints=sprints, user_stories=user_stories, users=users)
    else:
        return "Project not found", 404

# /////////////////////////////////////  Login  ///////////////////////////////////////////////////////////
@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if request.method == 'POST':
        # Get user input
        email = request.form['email']
        password = request.form['password']

        # Admin Login
        if email == 'admin@email.com' and password == 'password123':
            print("Admin logged in")
            session['logged_in'] = True
            session['user_role'] = 'admin'
            return redirect(url_for('admin_dashboard'))

        # Query the Users table to verify login credentials
        user = db.execute('SELECT * FROM Users WHERE Email=?', (email,)).fetchone()
        if user and user['Password'] == password:
            # Save user session data
            session['user_id'] = user['UserID']  # Save UserID in session
            session['user_name'] = user['UserName']  # Save UserName
            session['logged_in'] = True

            # Determine role
            role = None
            if db.execute('SELECT * FROM ProductOwner WHERE Email=?', (email,)).fetchone():
                role = 'product_owner'
            elif db.execute('SELECT * FROM ScrumMasters WHERE Email=?', (email,)).fetchone():
                role = 'scrum_master'
            else:
                role = 'user'
            session['user_role'] = role

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

# Route to display the login form
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     db = get_db()
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         role = request.form.get('role') 
#         if not role:
#             flash('Please select a role!', 'danger')
#             return redirect(url_for('login'))
#         # Query the database for the user
#         user = db.execute('SELECT * FROM Users WHERE UserName=?', (username,)).fetchone()
#         if user['Password'] == password:
#             flash('Login successful!', 'success')
#             session['user_role'] = role
#             session['user_name'] = username
#             session['logged_in'] = True
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Invalid username or password', 'danger')
#             return redirect(url_for('login'))
#     return render_template('login.html')

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    #email = request.form.get('email', '').strip()#
    #print(email)
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        #print(email)
        # Check if email exists in the database
        # user = User.query.filter_by(Email=email).first()
        # if not user:
        #     flash("Email address not found.", "danger")
        #     return redirect(url_for('forgotpassword'))

         # Generate token valid for 15 minutes (900 seconds)
        token = serializer.dumps(email, salt='password-reset-salt')

        # Generate the reset link with the token
        reset_link = url_for('reset_password', token=token, _external=True)
        # Email details
        sender_email = "ankitaisadoctor@gmail.com"
        sender_password = "ihkskbdmdlitzbbh"  # Use an app password if using Gmail
       # receiver_email = "aayushaayush438@gmail.com"
        subject = "Password Reset Request"
        body = f"Dear User,\n\nClick the link below to reset your password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email."
        try:
            send_email(sender_email, sender_password, email, subject, body)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f"Error sending email: {e}", "danger")
        return redirect(url_for('login'))
    return render_template('forgotpassword.html')       
        
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    
    try:
        # Validate token (expires in 900 seconds = 15 minutes)
        email = serializer.loads(token, salt='password-reset-salt', max_age=900)
    except Exception as e:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgotpassword'))


    if request.method == 'POST':
            new_password = request.form['new-password']
            confirm_password = request.form['confirm-password']
            # Check if passwords match
            if new_password != confirm_password:
                flash("Passwords do not match. Please try again.", "danger")
                return redirect(url_for('reset_password', token=token))


            # Here, you should hash the new password and update the user's password in the database
            #flash('Your password has been updated successfully!', 'success')
            #return redirect(url_for('reset_password'))
    #return render_template('reset_password.html', token=token)
            # Hash the new password before storing it
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

            #Update the user's password in the database
            user = User.query.filter_by(Email=email).first()#changes 
            user.Password = hashed_password
            db.session.commit()
            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the username or email already exists
        existing_user = User.query.filter_by(UserName=username).first()
        if existing_user:
            flash('Username already taken', 'danger')
            return redirect(url_for('signup'))
        
        existing_email = User.query.filter_by(Email=email).first()
        if existing_email:
            flash('Email already in use', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        # Hash the password before saving it to the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
         # Set the default role to 'User' (or any appropriate role)
        role = 'User'
        new_user = User(
            UserName=username,
            Email=email,
            Password=password,
            Role=role,  # Ensure the role is assigned
            ApprovalStatus='No'   # User is not approved initially
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created. Awaiting approval.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')

    return render_template('signup.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if request.method == 'POST':
        user_id = request.form.get('user_id')  # Get the user ID from the hidden field
        action = request.form.get('action')    # Get the action (approve or reject)

        # Fetch the user by ID
        user = User.query.get(user_id)
        if user:
            if action == 'approve':
                user.ApprovalStatus = 'Yes'  # Set approval status to Yes
                db = get_db()
                db.execute(
                    """
                    INSERT INTO Users (UserID, UserName, Password, Email) 
                    VALUES (?, ?, ?, ?)
                    """,
                    (user.UserID, user.UserName, user.Password, user.Email)
                    )
                db.commit()
            elif action == 'reject':
                user.ApprovalStatus = 'No'   # Set approval status to No
            try:
                db.commit()  # Commit the changes to the database
                flash(f"User {action}d successfully.", 'success')
            except Exception as e:
                db.session.rollback()  # Rollback if an error occurs
                flash(f"Error: {e}", 'danger')

        return redirect(url_for('admin_dashboard'))

    users = User.query.all()  # Fetch all users to display
    return render_template('admin_dashboard.html', users=users)

# Submit user data route
@app.route('/submit', methods=['POST'])
def submit_user():
    data = request.json  # Assuming you are sending data as JSON

    # Extract values from the request
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role')
    approved = data.get('approved')

    # Check if the username or email already exists
    existing_user = User.query.filter_by(UserName=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists!"}), 400

    existing_email = User.query.filter_by(Email=email).first()
    if existing_email:
        return jsonify({"message": "Email already in use!"}), 400

    # Create a new user record
    new_user = User(username=username, password=password, email=email, role=role, ApprovalStatus=approved)

    try:
        # Add to the database
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User data submitted successfully!"}), 200
    except IntegrityError as e:
        db.session.rollback()  # Rollback the transaction in case of an error
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# /////////////////////////////////////  Charts  ///////////////////////////////////////////////////////////
@app.route('/chart-data/donut/<int:project_id>')
@login_required
def donut_chart_data(project_id):
    db = get_db()

    # Get the task status distribution for the project, including statuses from the Tasks table
    data = db.execute('''
        SELECT TaskStatus, COUNT(T.TaskID) AS TaskCount
        FROM Tasks T
        JOIN UserStories US ON T.UserStoriesID = US.UserStoriesID
        WHERE US.ProjectID = ?
        GROUP BY TaskStatus;
    ''', (project_id,)).fetchall()

    # Extract labels (TaskStatus) and values (count of tasks for each status)
    labels = [row['TaskStatus'] for row in data]
    values = [row['TaskCount'] for row in data]

    # Return the task status distribution
    return jsonify({
        "labels": labels,
        "values": values
    })

@app.route('/chart-data/burnup/<int:project_id>')
@login_required
def burnup_chart_data(project_id):
    db = get_db()
    user_stories = db.execute('''
        SELECT SprintID, Status, StoryPoints
        FROM UserStories
        WHERE ProjectID = ?;
    ''', (project_id,)).fetchall()

    completed_sprint = {}
    total_sprint = {}

    for us in user_stories:
        # Total effort includes all story points in the sprint
        total_sprint[us['SprintID']] = total_sprint.get(us['SprintID'], 0) + us['StoryPoints']
        # Completed effort only includes completed story points
        if us['Status'] == 'Done':
            completed_sprint[us['SprintID']] = completed_sprint.get(us['SprintID'], 0) + us['StoryPoints']

    # Generate data for each sprint
    sprint_ids = sorted(set([us['SprintID'] for us in user_stories]))
    completed_data = [completed_sprint.get(sprint_id, 0) for sprint_id in sprint_ids]
    total_effort = [total_sprint.get(sprint_id, 0) for sprint_id in sprint_ids]

    return jsonify({
        "sprint_ids": [f"Sprint {i+1}" for i in range(len(sprint_ids))],  # Sprint labels
        "completed_data": completed_data,  # Completed efforts (green line)
        "total_effort": total_effort       # Total efforts (blue line)
    })

# Velocity Chart Data API
@app.route('/chart-data/velocity/<int:project_id>')
@login_required
def velocity_chart_data(project_id):
    db = get_db()
    user_stories = db.execute('''
        SELECT SprintID, Status, StoryPoints
        FROM UserStories
        WHERE ProjectID = ?;
    ''', (project_id,)).fetchall()

    total_story_points = {}
    completed_story_points = {}

    for us in user_stories:
        total_story_points[us['SprintID']] = total_story_points.get(us['SprintID'], 0) + us['StoryPoints']
        if us['Status'] == 'Done':
            completed_story_points[us['SprintID']] = completed_story_points.get(us['SprintID'], 0) + us['StoryPoints']

    sprint_ids = sorted(set([us['SprintID'] for us in user_stories]))
    total_data = [total_story_points.get(sprint_id, 0) for sprint_id in sprint_ids]
    completed_data = [completed_story_points.get(sprint_id, 0) for sprint_id in sprint_ids]

    return jsonify({
        "sprint_ids": [f"Sprint {i+1}" for i in range(len(sprint_ids))],
        "total_data": total_data,
        "completed_data": completed_data
    })

# Burndown Chart Data API
@app.route('/chart-data/burndown/<int:project_id>')
@login_required
def burndown_chart_data(project_id):
    db = get_db()
    user_stories = db.execute('''
        SELECT SprintID, Status, StoryPoints
        FROM UserStories
        WHERE ProjectID = ?;
    ''', (project_id,)).fetchall()
    remaining_sprint = {}
    for us in user_stories:
        if us['Status'] != 'Done':
            remaining_sprint[us['SprintID']] = remaining_sprint.get(us['SprintID'], 0) + us['StoryPoints']
    sprint_ids = sorted(set([us['SprintID'] for us in user_stories]))
    remaining_data = [remaining_sprint.get(sprint_id, 0) for sprint_id in sprint_ids]
    ideal_burn = [remaining_data[0] - (remaining_data[0] / len(sprint_ids)) * i for i in range(len(sprint_ids))]
    return jsonify({
        "sprint_ids": [f"Sprint {i+1}" for i in range(len(sprint_ids))],
        "remaining_data": remaining_data,
        "ideal_burn": ideal_burn
    })

@app.route('/chart-data/user-progress/<int:project_id>')
@login_required
def user_progress_chart_data(project_id):
    db = get_db()
    # Fetch user stories data
    user_stories = db.execute('''SELECT Assignee, StoryPoints, Status FROM UserStories WHERE ProjectID = ?;''', (project_id,)).fetchall()

    # Initialize dictionaries to track total and completed story points
    total_story_points = {}
    completed_story_points = {}

    for us in user_stories:
        assignee_id = us['Assignee']
        story_points = us['StoryPoints']
        status = us['Status'].strip().lower()  # Normalize the status to lowercase

        # Accumulate total story points
        total_story_points[assignee_id] = total_story_points.get(assignee_id, 0) + story_points

        # Accumulate completed story points only for completed status
        if status in ['completed', 'done']:
            completed_story_points[assignee_id] = completed_story_points.get(assignee_id, 0) + story_points

    # Fetch user information and map UserID to UserName
    users = db.execute('SELECT UserID, UserName FROM Users').fetchall()
    user_map = {user['UserID']: user['UserName'] for user in users}

    # Generate response data
    user_names = [user_map.get(user_id, f"User {user_id}") for user_id in total_story_points.keys()]  # Avoid "Unknown User"
    total_data = [total_story_points.get(user_id, 0) for user_id in total_story_points.keys()]
    completed_data = [completed_story_points.get(user_id, 0) for user_id in total_story_points.keys()]

    return jsonify({
        "user_names": user_names,
        "total_data": total_data,
        "completed_data": completed_data
    })

@app.route('/chart-data/user-ranking/<int:project_id>')
def user_ranking_chart_data(project_id):
    db = get_db()
    
    # Fetch user stories data
    user_stories = db.execute('''SELECT Assignee, StoryPoints, Status FROM UserStories WHERE ProjectID = ?;''', (project_id,)).fetchall()

    # Initialize dictionaries to track total and completed story points
    total_story_points = {}
    completed_story_points = {}

    for us in user_stories:
        assignee_id = us['Assignee']
        story_points = us['StoryPoints']
        status = us['Status'].strip().lower()  # Normalize the status to lowercase

        # Accumulate total story points
        total_story_points[assignee_id] = total_story_points.get(assignee_id, 0) + story_points

        # Accumulate completed story points only for completed status
        if status in ['completed', 'done']:
            completed_story_points[assignee_id] = completed_story_points.get(assignee_id, 0) + story_points

    # Fetch user information and map UserID to UserName
    users = db.execute('SELECT UserID, UserName FROM Users').fetchall()
    user_map = {user['UserID']: user['UserName'] for user in users}

    # Sort users by completed story points in descending order
    completed_sorted_users = sorted(completed_story_points.items(), key=lambda x: x[1], reverse=True)

    # Generate ranking data
    completed_user_names = [
        f"Rank {index + 1}: {user_map.get(user_id, f'User {user_id}')} "  # Avoid "Unknown User"
        for index, (user_id, _) in enumerate(completed_sorted_users)
    ]
    completed_data = [completed_story_points.get(user_id, 0) for user_id, _ in completed_sorted_users]
    total_data = [total_story_points.get(user_id, 0) for user_id, _ in completed_sorted_users]

    return jsonify({
        "completed_user_names": completed_user_names,
        "completed_data": completed_data,
        "total_data": total_data
    })

@app.route('/project/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    db = get_db()
    
    # Fetch project details along with the product owner name
    project = db.execute('''
        SELECT p.ProjectID, p.ProjectName, p.ProductOwnerID, p.StartDate, p.EndDate, p.RevisedEndDate, p.Status, po.Name
        FROM ProjectInfo p
        JOIN ProductOwner po ON p.ProductOwnerID = po.ProductOwnerID
        WHERE p.ProjectID = ?;
    ''', (project_id,)).fetchone()

    if project:
        if request.method == 'POST':
            # Retrieve form data
            name = request.form['name']
            product_owner_id = request.form['product_owner_id']  # Updated field name
            start_date = request.form['start_date']
            end_date = request.form['end_date']
            revised_date = request.form['revised_date']
            status = request.form['status']
            
            # Update project in the database
            db.execute('''
                UPDATE ProjectInfo
                SET ProjectName = ?, ProductOwnerID = ?, StartDate = ?, EndDate = ?, RevisedEndDate = ?, Status = ?
                WHERE ProjectID = ?
            ''', (name, product_owner_id, start_date, end_date, revised_date, status, project_id))
            
            db.commit()
            
            return redirect(url_for('project_overview', project_id=project_id))
        
        # Fetch the list of available product owners for the select dropdown (assuming you have multiple owners)
        product_owners = db.execute('SELECT ProductOwnerID, Name FROM ProductOwner').fetchall()
        
        return render_template('edit_project.html', project=project, product_owners=product_owners)
    else:
        return "Project not found", 404
@app.route('/project/update/<int:project_id>', methods=['POST'])
@login_required
def update_project(project_id):
    db = get_db()
    
    # Get the form data
    name = request.form['name']
    product_owner_id = request.form['product_owner_id']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    revised_date = request.form['revised_date']
    status = request.form['status']
    
    # Update project in the database
    db.execute('''
        UPDATE ProjectInfo
        SET ProjectName = ?, ProductOwnerID = ?, StartDate = ?, EndDate = ?, RevisedEndDate = ?, Status = ?
        WHERE ProjectID = ?
    ''', (name, product_owner_id, start_date, end_date, revised_date, status, project_id))
    
    db.commit()
    
    # Redirect to the project overview page after updating
    return redirect(url_for('project_overview', project_id=project_id))
@app.route('/project/update_user_story/<int:project_id>', methods=['POST'])
@login_required
def update_user_story(project_id):
    db = get_db()
    
    # Loop through the user stories and update based on the form data
    for story in request.form:
        if story.startswith('status_'):
            user_story_id = story.split('_')[1]
            status = request.form[story]
            sprint_id = request.form.get(f'sprint_{user_story_id}')
            
            # Update the status and sprint for the user story
            db.execute('''
                UPDATE UserStories
                SET Status = ?, SprintId = ?
                WHERE UserStoryID = ? AND ProjectID = ?
            ''', (status, sprint_id, user_story_id, project_id))
    
    db.commit()
    return redirect(url_for('project_overview', project_id=project_id))
@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    db = get_db()

    # Check if required tables exist
    required_tables = ['ProjectInfo', 'Sprints', 'UserStories', 'ScrumMasters', 'ProductOwner', 'Users']
    missing_tables = [table for table in required_tables if not table_exists(table)]
    if missing_tables:
        return f"The following tables are missing from the database: {', '.join(missing_tables)}", 500

    # Fetch Scrum Masters and Product Owners to display in the dropdown
    scrum_masters = db.execute('SELECT ScrumMasterID, Email FROM ScrumMasters').fetchall()
    product_owners = db.execute('SELECT ProductOwnerID, Name FROM ProductOwner').fetchall()
    team_members = db.execute('SELECT UserID, UserName FROM Users').fetchall()  # Fetch team members

    if request.method == 'POST':
        try:
            # Extract form data
            project_name = request.form.get('ProjectName')
            product_owner_id = request.form.get('ProductOwnerID')  # This should be a single value
            start_date = request.form.get('StartDate')
            end_date = request.form.get('EndDate')
            revised_end_date = request.form.get('RevisedEndDate')
            status = request.form.get('Status')

            # Determine the next ProjectID
            cur = db.execute("SELECT MAX(ProjectID) FROM ProjectInfo")
            result = cur.fetchone()
            next_project_id = result[0] + 1 if result[0] is not None else 1

            # Insert the project into ProjectInfo
            db.execute('''
                INSERT INTO ProjectInfo (ProjectID, ProjectName, ProductOwnerID, StartDate, EndDate, RevisedEndDate, Status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (next_project_id, project_name, product_owner_id, start_date, end_date, revised_end_date, status))

            # Insert selected team members into the junction table
            team_member_ids = request.form.getlist('TeamMembers')  # Get the list of selected team members
            
            # Ensure that we are passing one row for each member
            for member_id in team_member_ids:
                db.execute('''
                    INSERT INTO ProjectTeamMembers (ProjectID, UserID)
                    VALUES (?, ?)
                ''', (next_project_id, member_id))


            db.commit()

            # Save sprint data
            sprint_count = int(request.form.get('sprint_count', 0))
            for i in range(1, sprint_count + 1):
                sprint_start = request.form.get(f'sprint_{i}_start_date')
                sprint_end = request.form.get(f'sprint_{i}_end_date')
                sprint_status = request.form.get(f'sprint_{i}_status')
                scrum_master_id = request.form.get(f'sprint_{i}_scrum_master')  # Get Scrum Master selection

                # Determine the next SprintID
                cur = db.execute("SELECT MAX(SprintID) FROM Sprints")
                sprint_result = cur.fetchone()
                next_sprint_id = sprint_result[0] + 1 if sprint_result[0] is not None else 1

                # Insert into Sprints table
                db.execute('''
                    INSERT INTO Sprints (SprintID, ProjectID, SprintNo, ScrumMasterID, StartDate, EndDate, SprintStatus)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (next_sprint_id, next_project_id, i, scrum_master_id, sprint_start, sprint_end, sprint_status))
                db.commit()

            # Save user story data
            user_story_count = int(request.form.get('user_story_count', 0))
            for i in range(1, user_story_count + 1):
                story_title = request.form.get(f'story_{i}_title')
                moscow = request.form.get(f'story_{i}_moscow')
                assignee = request.form.get(f'story_{i}_assignee')
                story_status = request.form.get(f'story_{i}_status')
                story_points = request.form.get(f'story_{i}_points')
                sprint_no = int(request.form.get(f'story_{i}_sprint'))  # Sprint number from the form

                # Fetch SprintID for the given SprintNo and ProjectID
                sprint = db.execute('''
                    SELECT SprintID FROM Sprints
                    WHERE SprintNo = ? AND ProjectID = ?
                ''', (sprint_no, next_project_id)).fetchone()

                if not sprint:
                    return f"Invalid SprintNo {sprint_no} for User Story {i}. Please check the sprint details.", 400

                sprint_id = sprint[0]

                # Determine the next UserStoriesID
                cur = db.execute("SELECT MAX(UserStoriesID) FROM UserStories")
                user_story_result = cur.fetchone()
                next_user_story_id = user_story_result[0] + 1 if user_story_result[0] is not None else 1

                # Insert into UserStories table
                db.execute('''
                    INSERT INTO UserStories (UserStoriesID, ProjectID, UserStory, Moscow, Assignee, Status, StoryPoints, SprintID)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (next_user_story_id, next_project_id, story_title, moscow, assignee, story_status, story_points, sprint_id))
            db.commit()

        except sqlite3.OperationalError as e:
            if "locked" in str(e):
                return "Database is busy. Please try again later.", 500
            raise
        except ValueError as ve:
            return str(ve), 400
        finally:
            db.commit()

        # Redirect to dashboard after creating the project
        return redirect(url_for('dashboard'))

    # Render the form with Scrum Masters and Product Owners data
    return render_template('form.html', scrum_masters=scrum_masters, product_owners=product_owners, team_members=team_members)

if __name__ == '__main__':
    app.run(debug=True)
