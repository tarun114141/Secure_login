import firebase_admin
from firebase_admin import credentials, db
import bcrypt as br
import os
import random
import time
import smtplib
from email.message import EmailMessage

# ---------------- Firebase Configuration ---------------- #

cred = credentials.Certificate("firebase_api.json")

firebase_admin.initialize_app(
    cred,
    {
        "databaseURL": "https://login-74320-default-rtdb.asia-southeast1.firebasedatabase.app/"
    }
)

# ---------------- Email / OTP Functions ---------------- #

# Prefer a local config.py for quick global testing. Create `config.py` at
# project root with EMAIL_SENDER, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT,
# and EMAIL_DEBUG = True for local testing. Keep `config.py` out of source
# control (it's added to .gitignore by the helper below).
try:
    import config

    EMAIL_SENDER = getattr(config, "EMAIL_SENDER", None)
    EMAIL_PASSWORD = getattr(config, "EMAIL_PASSWORD", None)
    SMTP_SERVER = getattr(config, "SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(getattr(config, "SMTP_PORT", 587))
    EMAIL_DEBUG = bool(getattr(config, "EMAIL_DEBUG", True))
except Exception:
    EMAIL_SENDER = os.environ.get("EMAIL_SENDER")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    EMAIL_DEBUG = os.environ.get("EMAIL_DEBUG", "false").strip().lower() in ("1", "true", "yes")


def generate_otp(length=6):
    return "".join(str(random.randint(0, 9)) for _ in range(length))


def send_email_code(recipient_email, code):
    # If debug mode is enabled, just print to console
    if EMAIL_DEBUG:
        print(f"[DEBUG EMAIL] To: {recipient_email} Code: {code}")
        return
    
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        raise ValueError(
            "Email sender credentials are not configured. Set EMAIL_SENDER and EMAIL_PASSWORD in config.py or set EMAIL_DEBUG=True for local testing."
        )

    message = EmailMessage()
    message["Subject"] = "Your registration verification code"
    message["From"] = EMAIL_SENDER
    message["To"] = recipient_email
    message.set_content(
        f"Your registration verification code is: {code}\n\nThis code expires in 5 minutes."
    )

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
        smtp.send_message(message)


# ---------------- Password Functions ---------------- #

def hash_password(password):
    """
    Returns a bcrypt hashed password.
    """
    hashed_password = br.hashpw(
        password.encode("utf-8"),
        br.gensalt()
    )

    return hashed_password.decode("utf-8")


def verify_password(password, hashed_password):
    """
    Returns True if password matches the hash.
    """
    return br.checkpw(
        password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


# ---------------- Database Functions ---------------- #

def get_user(username):
    """
    Returns user data if user exists.
    Otherwise returns None.
    """
    username = username.strip().lower()

    ref = db.reference("users")

    return ref.child(username).get()


def save_user(username, email, hashed_password, verified=False):
    """
    Saves a new user into Firebase.
    """

    try:

        username = username.strip().lower()

        user = {
            "email": email,
            "password": hashed_password,
            "verified": verified
        }

        ref = db.reference("users")
        ref.child(username).set(user)

        return True

    except Exception as e:
        print("Error Saving User :", e)
        return False


# ---------------- Registration ---------------- #

def register_user(username, email, password, verified=False, raw_password=True):
    """
    Registers a new user.
    """

    username = username.strip().lower()

    # Check if username already exists
    if get_user(username):
        return False, "Username already exists"

    # Hash password only when passed as raw password
    hashed_password = password if not raw_password else hash_password(password)

    # Save user
    if save_user(username, email, hashed_password, verified=verified):
        return True, "Registration Successful"

    return False, "Could not register user"


# ---------------- Login ---------------- #

def login_user(username, password):
    """
    Logs in an existing user.
    """

    username = username.strip().lower()

    user = get_user(username)

    if user is None:
        return False, "Username does not exist"

    if verify_password(password, user["password"]):
        return True, "Login Successful"

    return False, "Incorrect Password"


# ---------------- Testing ---------------- #

if __name__ == "__main__":

    # Hashing Test
    password = "tarun114141"

    hashed = hash_password(password)

    print("Hashed Password:")
    print(hashed)

    print()

    print("Correct Password :", verify_password("tarun114141", hashed))
    print("Wrong Password   :", verify_password("wrongpassword", hashed))

    print()

    # Registration Test
    success, message = register_user(
        "Tarun",
        "tarun@gmail.com",
        "tarun114141"
    )

    print(message)

    # Login Test
    success, message = login_user(
        "Tarun",
        "tarun114141"
    )

    print(message)