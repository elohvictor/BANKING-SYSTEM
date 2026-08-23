import random
import hashlib
from flask import Flask, jsonify, request
from datetime import datetime,date, timezone
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

users = {}
accounts = {}
trasactions = {}

user_id_counter = 1
account_id_counter = 1
trasaction_id_counter = 1

ACCOUNT_TYPES = {"current", "savings"}

#---------------------------------------------------------------------------
#VALIDATIONS
#---------------------------------------------------------------------------
#Login validation
def loginPassword(password):
    password = generate_password_hash(password)
    return password

def verifyLoginPassword(saved_scrambled_string, user_input_attempt):
    return check_password_hash(saved_scrambled_string, user_input_attempt)

#Transaction validation 
SECRET_SERVER_SALT = "super-hidden-app-key-change-this"
def transactionPin(pin, account_number):
    secret_mixture = f"{pin}-{account_number}-{SECRET_SERVER_SALT}"
    
    pin = hashlib.sha256(secret_mixture.encode()).hexdigest()
    return pin

def verifyTransactionPin(saved_hashed_pin, pin_input_attempt, account_number):
    
    attempt_mixture = f"{pin_input_attempt}-{account_number}-{SECRET_SERVER_SALT}"
    attempt_hash = hashlib.sha256(attempt_mixture.encode()).hexdigest()
    
    return attempt_hash == saved_hashed_pin

#Account number validation
def generateAccountNumber():
    return str(random.randint(1000000000, 9999999999))

account_number = generateAccountNumber()
print(account_number)


# ---------------------------------------------------------------------------
# VALIDATION HELPERS
# ---------------------------------------------------------------------------
def validate_signup_payload(data, partial=False):
    errors = []
    cleaned = {}
    
    if not partial or "name" in data:
        name = data.get("name", "")
        if not isinstance(name, str) or not name.strip():
            errors.append("'name' is required and most be a non-empty string.")
        else:
            cleaned["name"] = name.strip()

    if not partial or "user_name" in data:
        user_name = data.get("user_name", "")
        if not isinstance(user_name, str) or not user_name.strip():
            errors.append("'user_name' is required and most be a non-empty string.")
        else:
            cleaned["user_name"] = user_name.strip()

    if not partial or "email" in data:
        email = data.get("email", "")
        if not isinstance(email, str) or "@" not in email:
            errors.append("'email' is required and must be a valid email address.")
        else:
            cleaned["email"] = email.strip().lower()

    if not partial or "password" in data:
        password = data.get("password", "")
        if not isinstance(password, str) or not any (char.isdigit() for char in password) or len(password) <6:
            errors.append("'password' is required and must be greater than 6.")
        else:
            cleaned["password"] = password.strip()

    return errors, cleaned

def validate_accountDetails_payload(data):
    errors = []
    cleaned = {}
    
    user_id = data.get("user_id")
    if not isinstance(user_id, int) or user_id not in users:
        errors.append("'user_id' is required and must reference an existing user.")
    else:
        cleaned["user_id"] = user_id

    account_type = data.get("account_type", "")
    if account_type not in ACCOUNT_TYPES:
        errors.append(f"'account_type' must be one of: {', '.join(sorted(ACCOUNT_TYPES))}.")
    else:
        cleaned["account_type"] = account_type


# ---------------------------------------------------------------------------
# USER ENDPOINTS  (full CRUD)
# ---------------------------------------------------------------------------
#get all users
@app.route("/user", methods=["GET"])
def retrieve_user():
    type_filter = request.args.get("account_type")
    active_filter = request.args.get("active")
    
    result  = list(users.values())
    
    if type_filter:
        result = [u for u in result if u["account_type"] == type_filter]

    if active_filter is not None:
        want_active = active_filter.lower() == "true"
        result = [u for u in result if u["active"] == want_active]

    return jsonify({"count": len(result), "user":result}), 200

#get each user
@app.route("/user/<int:user_id>", methods=["GET"])
def retrieve_each_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": f"User with id  {user_id} not found."}), 404
    
#create user
@app.route("/user/create", methods=["POST"])
def create_user():
    global user_id_counter
    
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"errors": "Request body must be valid JSON."}), 400
    errors, cleaned = validate_signup_payload(data)
    if errors:
        return jsonify({"errors": errors}), 400
    # Enforce unique email
    if any(u["email"] == cleaned["email"] for u in users.values()):
        return jsonify({"error": f"A user with email '{cleaned['email']}' already exists."}), 409
    
    new_user = {
        "id" : user_id_counter,
        "full_name" : cleaned["name"],
        "user_name" : cleaned["user_name"],
        "email": cleaned["email"],
        "password" : cleaned["password"],
        "account number" : account_number,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "message" : "Signup successful",
    }
    users[user_id_counter] = new_user
    user_id_counter += 1

    return jsonify(new_user), 201













if __name__ == "__main__":
    app.run(debug=True, port=5000)