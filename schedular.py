import sqlite3
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Database connection
DB_PATH = 'projects.db'

# Email credentials (update with your SMTP details)
EMAIL_ADDRESS = "talokarradhika@gmail.com"
EMAIL_PASSWORD = "gjfp modi xobt knqy"

# Function to send email notifications  
def send_email(to_address, subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to_address
        msg["Subject"] = subject
        
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())
        server.quit()
        print(f"Email sent to {to_address}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to check deadlines and send reminders
def check_deadlines_and_notify():
    try:
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()

        # Today's date
        today = datetime.now().date()

        # Query to get projects with approaching deadlines (within 7 days)
        cursor.execute("""
            SELECT ProjectID, ProjectName, ProductOwnerID, EndDate, Status
            FROM ProjectInfo
            WHERE DATE(EndDate) BETWEEN DATE(?) AND DATE(?)
        """, (today, today + timedelta(days=7)))
        
        projects = cursor.fetchall()

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
            cursor.execute("""
                SELECT COUNT(*) 
                FROM UserStories 
                WHERE ProjectID = ? AND Status NOT IN ('Done', 'Completed')
            """, (project_id,))
            pending_stories_count = cursor.fetchone()[0]

            # Fetch product owner's email
            cursor.execute("""
                SELECT Email
                FROM Users 
                WHERE UserID = ?
            """, (owner_id,))
            owner_email = cursor.fetchone()

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
            send_email(owner_email[0], email_subject, email_body)

        connection.close()
    except Exception as e:
        print(f"Error: {e}")

# Run the scheduler
if __name__ == "__main__":
    print("Running deadline reminder scheduler...")
    check_deadlines_and_notify()
