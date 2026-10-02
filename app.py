from flask import Flask, render_template, send_file, request, redirect, url_for, session
import boto3
import os
import io
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secret key for login sessions
app.secret_key = "cloud-storage-secret-key"

# --------------------------------------------------
# AWS CONFIGURATION
# --------------------------------------------------

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_BUCKET = os.getenv("AWS_BUCKET_NAME")


# Check AWS configuration
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_REGION or not S3_BUCKET:
    print("WARNING: AWS configuration is missing in .env")


# Connect to Amazon S3
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    # If already logged in, go to dashboard
    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # Demo login credentials
        if username == "admin" and password == "1234":

            session["user"] = username

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def home():

    # Protect dashboard
    if "user" not in session:
        return redirect(url_for("login"))

    try:

        response = s3.list_objects_v2(
            Bucket=S3_BUCKET
        )

        files = response.get("Contents", [])

        # Calculate total storage used
        total_size = sum(
            file.get("Size", 0)
            for file in files
        )

        return render_template(
            "dashboard.html",
            files=files,
            total_size=total_size
        )

    except Exception as e:

        return f"""
        <h2>Unable to connect to AWS S3</h2>
        <p>Please check your AWS configuration and .env file.</p>
        <p>Error: {e}</p>
        """


# --------------------------------------------------
# UPLOAD
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")

    if file and file.filename:

        try:

            s3.upload_fileobj(
                file,
                S3_BUCKET,
                file.filename
            )

        except Exception as e:

            return f"""
            <h2>Upload failed</h2>
            <p>{e}</p>
            """

    return redirect(url_for("home"))


# --------------------------------------------------
# DOWNLOAD
# --------------------------------------------------

@app.route("/download/<path:filename>")
def download_file(filename):

    if "user" not in session:
        return redirect(url_for("login"))

    try:

        file_object = s3.get_object(
            Bucket=S3_BUCKET,
            Key=filename
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


# --------------------------------------------------
# DELETE
# --------------------------------------------------

@app.route("/delete/<path:filename>")
def delete_file(filename):

    if "user" not in session:
        return redirect(url_for("login"))

    try:

        s3.delete_object(
            Bucket=S3_BUCKET,
            Key=filename
        )

    except Exception as e:

        return f"""
        <h2>Delete failed</h2>
        <p>{e}</p>
        """

    return redirect(url_for("home"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)