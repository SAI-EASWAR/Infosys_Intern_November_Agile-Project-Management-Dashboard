import sqlite3
import smtplib
from datetime import datetime, timedelta
from send_email import send_email
from email.mime.multipart import MIMEMultipart

# Database connection
DATABASE = 'projects.db'
# Email credentials (update with your SMTP details)
EMAIL_ADDRESS = "talokarradhika@gmail.com"
EMAIL_PASSWORD = "gjfp modi xobt knqy"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL;')  # Enable WAL mode
    return db

# Function to check deadlines and send reminders
def check_deadlines_and_notify():
    try:
        db = get_db()
        # Today's date
        today = datetime.now().date()
        # Query to get projects with approaching deadlines (within 7 days)
        projects = db.execute("""
            SELECT ProjectID, ProjectName, ProductOwnerID, EndDate, Status
            FROM ProjectInfo
            WHERE DATE(EndDate) BETWEEN DATE(?) AND DATE(?)
        """, (today, today + timedelta(days=7))).fetchall()
        if not projects:
            print("No projects with approaching deadlines.")
            return
        # Loop through the projects
        for project in projects:
            project_id, project_name, owner_id, end_date, status = project
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
            # Skip if project status is completed
            if status.lower() == "completed":
                continue
            # Check pending user stories
            pending_stories_count = db.execute("""SELECT COUNT(*) FROM UserStories WHERE ProjectID = ? AND Status NOT IN ('Done', 'Completed')""", (project_id,)).fetchone()[0]
            # Fetch product owner's email
            owner_email = db.execute("""SELECT Email FROM Users WHERE UserID = ?""", (owner_id,)).fetchone()
            if not owner_email:
                print(f"No email found for Product Owner (ID: {owner_id}). Skipping...")
                continue
            # Calculate remaining days
            days_left = (end_date - today).days
            # Prepare and send the email
            email_subject = f"Reminder: {project_name} deadline in {days_left} days!"
            email_body = f"""
            Dear Product Owner,

            This is a reminder that the project '{project_name}' has {days_left} day(s) remaining until the deadline on {end_date}.

            Project Status: {status}
            Pending User Stories: {pending_stories_count}

            Please take the necessary actions to ensure the project is on track.

            Best regards,
            Agile Project Dashboard
            """
            send_email(EMAIL_ADDRESS, EMAIL_PASSWORD, owner_email[0], email_subject, email_body)
        connection.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Running deadline reminder scheduler...")
    check_deadlines_and_notify()
