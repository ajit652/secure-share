from flask import Flask, render_template, request, redirect, session, flash, send_file
from pymongo import MongoClient
from cryptography.fernet import Fernet
import gridfs
import io
import hashlib
import uuid
import os
from bson.objectid import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------
# Encryption Key
# ---------------------------
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
    return open("secret.key", "rb").read()

key = load_key()
cipher = Fernet(key)

# ---------------------------
# Flask Setup
# ---------------------------
app = Flask(__name__)
app.secret_key = "supersecurekey"

# ---------------------------
# Admin Credentials
# ---------------------------
ADMIN_USERNAME = "ajit"
ADMIN_PASSWORD = "Ajit@12345"

# ---------------------------
# MongoDB Atlas Connection
# ---------------------------
MONGO_URI = "mongodb+srv://ajitsahoo9638705_db_user:Ajit%4012345@seecuresharecluster.ukow3lw.mongodb.net/?retryWrites=true&w=majority"

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

db = client["ajitDB"]

fs = gridfs.GridFS(db)

users_collection = db["users"]
files_collection = db["files"]
downloads_collection = db["downloads"]

# ---------------------------
# Home
# ---------------------------
@app.route("/")
def home():
    return redirect("/login")

# ---------------------------
# Register
# ---------------------------
@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if users_collection.find_one({"username": username}):
            flash("Username already exists")
            return redirect("/register")

        user_id = str(uuid.uuid4())

        users_collection.insert_one({
            "username": username,
            "user_id": user_id,
            "password": generate_password_hash(password)
        })

        flash("Registration successful")
        return redirect("/login")

    return render_template("register.html")

# ---------------------------
# Login
# ---------------------------
@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        # Admin login
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session["admin"] = True
            session["username"] = "Admin"
            return redirect("/admin_dashboard")

        user = users_collection.find_one({"username": username})

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = username

            return redirect("/dashboard")

        flash("Invalid credentials")

    return render_template("login.html")

# ---------------------------
# User Dashboard
# ---------------------------
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    files = files_collection.find({
        "$or":[
            {"receiver_id": user_id},
            {"uploader_id": user_id}
        ]
    }).sort("timestamp",-1).limit(50)

    return render_template(
        "index.html",
        files=files,
        current_user=session["username"]
    )

# ---------------------------
# Upload
# ---------------------------
@app.route("/upload", methods=["GET","POST"])
def upload():

    if "user_id" not in session:
        return redirect("/login")

    users = users_collection.find({"user_id":{"$ne": session["user_id"]}}).limit(50)

    if request.method == "POST":

        file = request.files["file"]
        receiver = request.form["receiver"]
        password = request.form.get("filepassword")

        if not file:
            flash("Select a file")
            return redirect("/upload")

        password_hash = None
        if password:
            password_hash = hashlib.sha256(password.encode()).hexdigest()

        encrypted_data = cipher.encrypt(file.read())

        file_id = fs.put(encrypted_data, filename=file.filename)

        files_collection.insert_one({
            "file_id": file_id,
            "filename": file.filename,
            "uploader_id": session["user_id"],
            "receiver_id": receiver,
            "password": password_hash,
            "timestamp": datetime.now()
        })

        downloads_collection.insert_one({
            "user_id": session["user_id"],
            "filename": file.filename,
            "action": "upload",
            "timestamp": datetime.now()
        })

        flash("File uploaded successfully")
        return redirect("/dashboard")

    return render_template("upload.html", users=users)

# ---------------------------
# Download
# ---------------------------
@app.route("/download/<file_id>", methods=["GET","POST"])
def download(file_id):

    if "user_id" not in session:
        return redirect("/login")

    file_info = files_collection.find_one({"file_id": ObjectId(file_id)})

    if not file_info:
        flash("File not found")
        return redirect("/dashboard")

    if file_info.get("password"):

        if request.method == "POST":

            entered = hashlib.sha256(request.form["password"].encode()).hexdigest()

            if entered != file_info["password"]:
                flash("Wrong password")
                return redirect(request.url)

            grid_file = fs.get(file_info["file_id"])
            decrypted = cipher.decrypt(grid_file.read())

            return send_file(
                io.BytesIO(decrypted),
                download_name=file_info["filename"],
                as_attachment=True
            )

        return render_template("download.html", file=file_info, password_required=True)

    grid_file = fs.get(file_info["file_id"])
    decrypted = cipher.decrypt(grid_file.read())

    return send_file(
        io.BytesIO(decrypted),
        download_name=file_info["filename"],
        as_attachment=True
    )

# ---------------------------
# Delete
# ---------------------------
@app.route("/delete/<file_id>")
def delete(file_id):

    if "user_id" not in session:
        return redirect("/login")

    file = files_collection.find_one({"file_id": ObjectId(file_id)})

    if not file:
        flash("File not found")
        return redirect("/dashboard")

    if file["uploader_id"] != session["user_id"]:
        flash("Permission denied")
        return redirect("/dashboard")

    fs.delete(file["file_id"])
    files_collection.delete_one({"file_id": ObjectId(file_id)})

    flash("File deleted")
    return redirect("/dashboard")

# ---------------------------
# History
# ---------------------------
@app.route("/history")
def history():

    if "user_id" not in session:
        return redirect("/login")

    logs = downloads_collection.find({
        "user_id": session["user_id"]
    }).sort("timestamp",-1).limit(50)

    return render_template("history.html", logs=logs)

# ===========================
# ADMIN DASHBOARD
# ===========================

@app.route("/admin_dashboard")
def admin_dashboard():

    if "admin" not in session:
        return redirect("/login")

    users = list(users_collection.find().limit(50))
    files = list(files_collection.find().limit(50))
    logs = list(downloads_collection.find().sort("timestamp",-1).limit(50))

    user_count = users_collection.count_documents({})
    file_count = files_collection.count_documents({})
    log_count = downloads_collection.count_documents({})

    return render_template(
        "admin_dashboard.html",
        users=users,
        files=files,
        logs=logs,
        user_count=user_count,
        file_count=file_count,
        log_count=log_count
    )

# ---------------------------
# Admin Logout
# ---------------------------
@app.route("/admin_logout")
def admin_logout():

    session.clear()
    return redirect("/login")

# ---------------------------
# Logout
# ---------------------------
@app.route("/logout")
def logout():

    session.clear()
    flash("Logged out")
    return redirect("/login")

# ---------------------------
# Run Flask
# ---------------------------
if __name__ == "__main__":
    app.run()