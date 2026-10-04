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
import psycopg2

from psycopg2.extras import RealDictCursor
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
            verified INTEGER DEFAULT 1
        )
    """)

    connection.commit()

    cursor.close()
    connection.close()


create_database()


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for("home")
        )


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
            """
            SELECT *
            FROM users
            WHERE email = %s
            """,
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
        # LOGIN SUCCESS
        # -------------------------------------------------

        session["user_id"] = user["id"]

        session["username"] = user["username"]

        session["email"] = user["email"]


        return redirect(
            url_for("home")
        )


    return render_template(
        "login.html"
    )


# =========================================================
# SIGN UP
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if "user_id" in session:

        return redirect(
            url_for("home")
        )


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

        if (
            not username
            or not email
            or not password
        ):

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
            """
            SELECT *
            FROM users
            WHERE email = %s
            """,
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
            (
                username,
                email,
                password,
                verified
            )
            VALUES (%s, %s, %s, 1)
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
        # LOGIN NEW USER
        # -------------------------------------------------

        session["user_id"] = user_id

        session["username"] = username

        session["email"] = email


        return redirect(
            url_for("home")
        )


    return render_template(
        "signup.html"
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
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
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


        # -------------------------------------------------
        # DISPLAY FILE NAME
        # -------------------------------------------------

        for file in files:

            file["DisplayName"] = file[
                "Key"
            ].replace(
                prefix,
                "",
                1
            )


        total_size = sum(
            file.get(
                "Size",
                0
            )
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

@app.route(
    "/upload",
    methods=["POST"]
)
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


        s3_key = (
            f"users/{user_id}/{filename}"
        )


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

@app.route(
    "/download/<path:filename>"
)
def download_file(filename):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]


    filename = os.path.basename(
        filename
    )


    s3_key = (
        f"users/{user_id}/{filename}"
    )


    try:

        file_object = s3.get_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )


        return send_file(

            io.BytesIO(
                file_object[
                    "Body"
                ].read()
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

@app.route(
    "/delete/<path:filename>"
)
def delete_file(filename):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]


    filename = os.path.basename(
        filename
    )


    s3_key = (
        f"users/{user_id}/{filename}"
    )


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
