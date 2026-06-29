import os
import time
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)
from auth import *


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "helloitsme_nn_")



@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    success, message = login_user(username, password)

    if not success:
        return render_template(
            "login.html",
            error=message
        )

    user = get_user(username)

    if user is None or not user.get("verified", False):
        return render_template(
            "login.html",
            error="Account not verified. Please register again and verify your email."
        )

    session["username"] = username
    return redirect(url_for("dashboard"))


@app.route("/verify", methods=["GET", "POST"])
def verify():

    if "pending_registration" not in session:
        return redirect(url_for("register"))

    if request.method == "GET":
        return render_template("verify.html")

    code = request.form.get("code", "").strip()
    pending_data = session.get("pending_registration", {})
    otp_code = pending_data.get("otp_code")
    sent_at = pending_data.get("otp_sent_at", 0)

    if otp_code is None or time.time() - sent_at > 300:
        session.pop("pending_registration", None)
        return render_template(
            "register.html",
            error="Verification code expired. Please register again."
        )

    if code != otp_code:
        return render_template(
            "verify.html",
            error="Incorrect verification code. Please try again."
        )

    username = pending_data["username"]
    email = pending_data["email"]
    password_hash = pending_data["password_hash"]

    success, message = register_user(username, email, password_hash, verified=True, raw_password=False)

    if not success:
        return render_template(
            "register.html",
            error=message
        )

    session.pop("pending_registration", None)
    session["username"] = username
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if password != confirm_password:
        return render_template(
            "register.html",
            error="Passwords do not match"
        )

    if get_user(username):
        return render_template(
            "register.html",
            error="Username already exists"
        )

    password_hash = hash_password(password)
    otp_code = generate_otp()
    session["pending_registration"] = {
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "otp_code": otp_code,
        "otp_sent_at": int(time.time())
    }

    try:
        send_email_code(email, otp_code)
    except ValueError as exc:
        session.pop("pending_registration", None)
        return render_template(
            "register.html",
            error=str(exc)
        )
    except Exception:
        session.pop("pending_registration", None)
        return render_template(
            "register.html",
            error="Unable to send verification email. Please check your SMTP credentials and network settings."
        )

    return redirect(url_for("verify"))


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])

    return render_template(
    "dashboard.html",
    username=session["username"],
    email=user["email"]
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))



if __name__ == "__main__":
    app.run(debug=True)