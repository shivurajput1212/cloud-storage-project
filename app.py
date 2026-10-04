from flask import (
    Flask,
    render_template,
    send_file,
    request,
    redirect,
    url_for,
    session
)

import boto3
import os
import io
import random
import smtplib
import psycopg2

from psycopg2.extras import RealDictCursor
from email.message import EmailMessage
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)


# =========================================================
# AWS CONFIGURATION
# =========================================================

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_BUCKET = os.getenv("AWS_BUCKET_NAME")

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)


# =========================================================
# EMAIL CONFIGURATION
# =========================================================

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


# =========================================================
# POSTGRESQL DATABASE
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")


def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


def create_database():

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        )
    """)

    connection.commit()
    cursor.close()
    connection.close()


create_database()


# =========================================================
# OTP FUNCTIONS
# =========================================================

def generate_otp():

    return str(random.randint(100000, 999999))


def send_otp_email(receiver_email, otp):

    if not SMTP_EMAIL or not SMTP_PASSWORD:

        print("WARNING: SMTP_EMAIL or SMTP_PASSWORD is missing.")
        print("OTP for", receiver_email, "is:", otp)

        return False

    message = EmailMessage()

    message["Subject"] = "CloudStorage Verification Code"
    message["From"] = SMTP_EMAIL
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your CloudStorage verification code is:

{otp}

This code is valid for this verification process.

If you did not request this code, you can ignore this email.

CloudStorage
"""
    )

    try:

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT
        ) as server:

            server.starttls()

            server.login(
                SMTP_EMAIL,
                SMTP_PASSWORD
            )

            server.send_message(message)

        return True

    except Exception as e:

        print("Email error:", e)

        return False


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:

        return redirect(url_for("home"))

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        if not check_password_hash(
            user["password"],
            password
        ):

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        # -------------------------------------------------
        # EMAIL VERIFICATION CHECK
        # -------------------------------------------------

        if user["verified"] == 0:

            otp = generate_otp()

            session["verification_user_id"] = user["id"]
            session["verification_email"] = user["email"]
            session["verification_otp"] = otp

            send_otp_email(
                user["email"],
                otp
            )

            return redirect(
                url_for("verify_login")
            )

        # -------------------------------------------------
        # SEND OTP FOR LOGIN
        # -------------------------------------------------

        otp = generate_otp()

        session["login_user_id"] = user["id"]
        session["login_email"] = user["email"]
        session["login_otp"] = otp

        send_otp_email(
            user["email"],
            otp
        )

        return redirect(
            url_for("verify_login")
        )

    return render_template("login.html")


# =========================================================
# SIGN UP
# =========================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if "user_id" in session:

        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # -------------------------------------------------
        # BASIC VALIDATION
        # -------------------------------------------------

        if not username or not email or not password:

            return render_template(
                "signup.html",
                error="Please fill all fields."
            )

        if password != confirm_password:

            return render_template(
                "signup.html",
                error="Passwords do not match."
            )

        if len(password) < 6:

            return render_template(
                "signup.html",
                error="Password must contain at least 6 characters."
            )

        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            cursor.close()
            connection.close()

            return render_template(
                "signup.html",
                error="An account with this email already exists."
            )

        # -------------------------------------------------
        # CREATE USER
        # -------------------------------------------------

        hashed_password = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users
            (username, email, password, verified)
            VALUES (%s, %s, %s, 0)
            RETURNING id
            """,
            (
                username,
                email,
                hashed_password
            )
        )

        user_id = cursor.fetchone()["id"]

        connection.commit()

        cursor.close()
        connection.close()

        # -------------------------------------------------
        # CREATE OTP
        # -------------------------------------------------

        otp = generate_otp()

        session["verification_user_id"] = user_id
        session["verification_email"] = email
        session["verification_otp"] = otp

        send_otp_email(
            email,
            otp
        )

        return redirect(
            url_for("verify_signup")
        )

    return render_template("signup.html")


# =========================================================
# SIGNUP OTP VERIFICATION
# =========================================================

@app.route("/verify-signup", methods=["GET", "POST"])
def verify_signup():

    if "verification_user_id" not in session:

        return redirect(url_for("signup"))

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        saved_otp = session.get(
            "verification_otp"
        )

        if entered_otp != saved_otp:

            return render_template(
                "verify.html",
                error="Invalid verification code."
            )

        user_id = session["verification_user_id"]

        connection = get_db()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET verified = 1
            WHERE id = %s
            """,
            (user_id,)
        )

        connection.commit()

        cursor.close()
        connection.close()

        session.pop(
            "verification_user_id",
            None
        )

        session.pop(
            "verification_email",
            None
        )

        session.pop(
            "verification_otp",
            None
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "verify.html"
    )


# =========================================================
# LOGIN OTP VERIFICATION
# =========================================================

@app.route("/verify-login", methods=["GET", "POST"])
def verify_login():

    if "login_user_id" not in session:

        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        saved_otp = session.get(
            "login_otp"
        )

        if entered_otp != saved_otp:

            return render_template(
                "verify.html",
                error="Invalid verification code."
            )

        user_id = session["login_user_id"]

        session["user_id"] = user_id

        session.pop(
            "login_user_id",
            None
        )

        session.pop(
            "login_email",
            None
        )

        session.pop(
            "login_otp",
            None
        )

        return redirect(
            url_for("home")
        )

    return render_template(
        "verify.html"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def home():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        (user_id,)
    )

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:

        session.clear()

        return redirect(
            url_for("login")
        )

    # -----------------------------------------------------
    # USER-SPECIFIC S3 FOLDER
    # -----------------------------------------------------

    prefix = f"users/{user_id}/"

    try:

        response = s3.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=prefix
        )

        files = response.get(
            "Contents",
            []
        )

        # Remove folder path from displayed filename
        for file in files:

            file["DisplayName"] = file["Key"].replace(
                prefix,
                "",
                1
            )

        total_size = sum(
            file.get("Size", 0)
            for file in files
        )

        return render_template(
            "dashboard.html",
            files=files,
            total_size=total_size,
            username=user["username"],
            email=user["email"]
        )

    except Exception as e:

        return f"""
        <h2>Unable to connect to AWS S3</h2>
        <p>Please check your AWS configuration.</p>
        <p>Error: {e}</p>
        """


# =========================================================
# UPLOAD
# =========================================================

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    file = request.files.get(
        "file"
    )

    if file and file.filename:

        user_id = session["user_id"]

        filename = os.path.basename(
            file.filename
        )

        s3_key = f"users/{user_id}/{filename}"

        try:

            s3.upload_fileobj(
                file,
                S3_BUCKET,
                s3_key
            )

        except Exception as e:

            return f"""
            <h2>Upload failed</h2>
            <p>{e}</p>
            """

    return redirect(
        url_for("home")
    )


# =========================================================
# DOWNLOAD
# =========================================================

@app.route("/download/<path:filename>")
def download_file(filename):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    filename = os.path.basename(
        filename
    )

    s3_key = f"users/{user_id}/{filename}"

    try:

        file_object = s3.get_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )

        return send_file(
            io.BytesIO(
                file_object["Body"].read()
            ),
            download_name=filename,
            as_attachment=True
        )

    except Exception as e:

        return f"""
        <h2>Download failed</h2>
        <p>{e}</p>
        """


# =========================================================
# DELETE
# =========================================================

@app.route("/delete/<path:filename>")
def delete_file(filename):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    filename = os.path.basename(
        filename
    )

    s3_key = f"users/{user_id}/{filename}"

    try:

        s3.delete_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )

    except Exception as e:

        return f"""
        <h2>Delete failed</h2>
        <p>{e}</p>
        """

    return redirect(
        url_for("home")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )
