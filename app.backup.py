from flask import Flask, redirect
import boto3
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

bucket_name = os.getenv("AWS_BUCKET_NAME")

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION")
)

@app.route("/")
def home():
    return "Cloud Storage Project is connected to AWS S3!"

@app.route("/files")
def files():
    response = s3.list_objects_v2(Bucket=bucket_name)

    html = "<h2>My Cloud Files</h2>"

    if "Contents" in response:
        for file in response["Contents"]:
            file_name = file["Key"]

            url = s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": bucket_name,
                    "Key": file_name
                },
                ExpiresIn=3600
            )

            html += f'<p><a href="{url}" target="_blank">{file_name}</a></p>'

    return html

app.run(debug=True)