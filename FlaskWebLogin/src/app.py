from flask import Flask, render_template, request, url_for, redirect, session, flash
import os
from flask_sqlalchemy import SQLAlchemy
import bcrypt

# Create the Flask app
app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret! (This is for session)
key = os.environ.get("SECRET_KEY")
app.secret_key = str(key)

# Set the database URI
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Push the app context
app.app_context().push()

# Create the database object
db = SQLAlchemy(app)

# Create the database model
class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    salt = db.Column(db.String(100))

    def __init__(self, name, email, password, salt):
        self.name = name
        self.email = email
        self.password = password
        self.salt = salt

# Create the routes these are the backend scripts that run when a user visits a page
@app.route("/")
def home():
    # Redirect the user to the login page
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # Check if the user is already logged in
    if request.method == "POST":
        # Get the username and password from the form
        username = request.form["username"]
        password = request.form["password"]
        
        # Check if the user is in the database
        found_user = users.query.filter_by(name=username).first()

        # If the user is in the database, log them in
        if found_user:
            # Check if the password is correct
            if bcrypt.checkpw(password.encode("utf-8"), found_user.password):
                # Save the user in the session
                session["user"] = username
                flash("You have been logged in!", username)
                return redirect(url_for("user"))
            else:
                # If the password is incorrect, redirect them to the login page
                flash("Incorrect password!")
        # If the user is not in the database redirect them to the signup page
        else:
            flash("User not found please sign up or try again!")
    # If the user is not logged in, render the login page
    else:
        # Check if the user is already logged in
        if "user" in session:
            flash("You are already logged in!")
            return redirect(url_for("user"))
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Get the username and password from the form
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        # Check if the user is in the database
        found_user = users.query.filter_by(name=username).first()
        # If the user is in the database, redirect them to the login page
        if found_user:
            flash("User already exists!")
            return redirect(url_for("login"))
        # If the user is not in the database, add them to the database
        else:
            # Hash the password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
            # Add the user to the database
            user = users(username, email, hashed_password, salt)
            db.session.add(user)
            db.session.commit()
            flash("You have been signed up!", username)
            return redirect(url_for("user"))
    # If the user is not logged in, render the login page
    else: 
        # Check if the user is already logged in
        if "user" in session:
            flash("You are already logged in!")
            return redirect(url_for("user"))
    return render_template("signup.html")

@app.route("/user")
def user():
    # Check if the user is logged in
    if "user" in session:
        username = session["user"]
        user = users.query.filter_by(name=username).first()
        return render_template("user.html", user=user)
    else:
        return redirect(url_for("home"))

@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Log the user out by popping the session
    session.pop("user", None)

    #deletes the email in the session
    if "email" in session:
        session.pop("email", None)

    #alert the user that they have been logged out by creating a flash message
    flash("You have been logged out!", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    # init the database
    db.create_all()
    # Run the app (debugmode helps by displaying the backend errors in the browser)
    app.run(debug=True)