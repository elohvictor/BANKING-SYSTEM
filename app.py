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
DEFAULT_CURRENCY = {"NGN"}
TRANSACTION_TYPE = {"deposite", "withdrawl", "transfer"}

#---------------------------------------------------------------------------
#VALIDATIONS
#---------------------------------------------------------------------------
#Login validation
def loginPassword(password):
    password = generate_password_hash(password)
    return password

def verifyLoginPassword(saved_scrambled_string, user_input_attempt):
    return check_password_hash(saved_scrambled_string, user_input_attempt)

def login_password(loginPassword, verifyLoginPassword):
    if loginPassword() == verifyLoginPassword():
        return True
    else:
        return False

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

def transaction_pin(transactionPin, verifyTransactionPin):
    if transactionPin() == verifyTransactionPin():
        return True
    else:
        return False

#Account number validation
def generateAccountNumber():
    return str(random.randint(1000000000, 9999999999))

account_number = generateAccountNumber()
print(account_number)


# ---------------------------------------------------------------------------
# VALIDATION HELPERS
# ---------------------------------------------------------------------------
#SINGUP PAYLOAD
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
        if not isinstance(email, str) or "@" and "." not in email:
            errors.append("'email' is required and must be a valid email address.")
        else:
            cleaned["email"] = email.strip().lower()

    
        password = data.get("password", "")
        if not isinstance(password, str) or not any (char.isdigit() for char in password) or len(password) <6:
            errors.append("'password' is required and must be greater than 6.")
        else:
            cleaned["password"] = password.strip()

    return errors, cleaned

#ACCOUNT DETAILS
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

    currency = data.get("currency", "")
    if currency != DEFAULT_CURRENCY:
        errors.append(f"'currency' must be: {', '.join(sorted(DEFAULT_CURRENCY))}.")
    else:
        cleaned["currency"] = currency
        
    pin = data.get("pin", "")
    if not isinstance(transactionPin(pin), int) or not len(pin) == 4:
        errors.append("'pin' is required and must be exactly four(4) digit.")
    else:
        cleaned["pin"] = pin.strip()
        
        
def login_payload(data):
    errors = []
    cleaned = {}
    
    user_id = data.get("user_id")
    if not isinstance(user_id, int) or user_id not in users:
        errors.append("'user_id' is required and must reference an existing user.")
    else:
        cleaned["user_id"] = user_id

    password = data.get("password", "") 
    if not isinstance(password, str) or not password.strip():
        errors.append("'password' is required and most be a non-empty string.")
    else:
        cleaned["password"] = password.strip()
    return errors, cleaned


#TRANSACTION PAYLOAD
def validate_transaction_payload(data, partial=False):
    errors = []
    cleaned = {}

    if not partial or "transaction_type" in data:
        transaction_type = data.get("transaction_type", "")
        if transaction_type not in TRANSACTION_TYPE:
            errors.append(f"'transaction type' must be one of: {', '.join(sorted(TRANSACTION_TYPE))}.")
        else:
            cleaned["transaction_type"] = transaction_type


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
    return jsonify(user), 200

#create user
@app.route("/user/signup", methods=["POST"])
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
        "password" : loginPassword(cleaned["password"]),
        "account_nuber" : account_number,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "message" : "Signup successful",
    }
    users[user_id_counter] = new_user
    user_id_counter += 1

    return jsonify(new_user), 201

#update user
@app.route("/user/<int:user_id>", methods = ["PUT"])
def update_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error" : f"User with id {user_id} not found."}), 404

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    errors, cleaned = validate_signup_payload(data, partial=True)
    if errors:
        return jsonify({"errors": errors}), 400

    if not cleaned:
        return jsonify({"error": "No valid fields provided to update."}), 400

    user.update(cleaned)
    return jsonify(user), 200

#deactivate user
@app.route("/user/<int:user_id>", methods=["DELETE"])
def deactivate_user(user_id):
    
    user = users.get(user_id)
    if not user:
        return jsonify({"error": f"User with id {user_id} not found."}), 404
    user["active"] = False
    return "", 204

#login 
@app.route("/user/login", methods=["POST"])
def login_user():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"errors": "Request body must be valid JSON."}), 400

    errors, cleaned = login_payload(data)
    if errors:
        return jsonify({"errors": errors}), 400
        
    for user in users:
        if verifyLoginPassword(user["password"], cleaned["password"]):
            login_user = {
                "Password" : cleaned["password"],
                "message" : "login successful",
                "user_id" : cleaned["user_id"],
            }
            return jsonify(login_user), 200
        return jsonify({"error": "Incorrect pin"}), 401




#---------------------------------------------------------------------------
# ACCOUNT ENDPOINTS  (create + read-heavy, hard delete for corrections)
# --------------------------------------------------------------------------
#get all account detail
@app.route("/details", methods=["GET"])
def get_details():
    
    user_id = request.args.get("user_id", type=int)
    
    result = list(account_details.values)
    
    if user_id is not None:
        result = [s for s in result if s["user_id"] == user_id]
        
    return jsonify({"count": len(result), "details": result}), 200

#get each user details
@app.route("/details/<int:account_id>", methods=["GET"])
def retrieve_single_detail(account_id):
    detail = account_details.get(account_id)
    if not detail:
        return jsonify({"error": f"Account detail with id {account_id} not fount."}), 404
    return jsonify(detail), 200

#account detail
@app.route("/account", methods=["POST"])
def account_details():
    global account_id_counter
    
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"errors": "Request body must be valid JSON."}), 400
    errors, cleaned = validate_accountDetails_payload(data)
    if errors:
        return jsonify({"errors": errors}), 400

    #Block account details from deactivating user
    customer = users[cleaned["user_id"]]
    if not customer["active"]:
        return jsonify({"error": "Cannot record an account deatail for an inactive user."}), 409

    account_detail = {
        "id": account_id_counter,
        "user_id": cleaned["user_id"],
        "account_type": cleaned["account_type"],
        "currency": cleaned["currency"],
        "account_number": account_number,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    account_detail[account_id_counter] = account_detail
    account_id_counter += 1

    return jsonify(account_detail)

#delete detail
@app.route("/account/<int:account_id>", methods=["DELETE"])
def delete_sale(account_id):
    
    if account_id not in account_details:
        return jsonify({"error": f"Sale with id {account_id} not found."}), 404

    del account_details[account_id]
    return "", 204

#---------------------------------------------------------------------------
# TRANSACTION ENPOINTS 
# --------------------------------------------------------------------------
def transaction_type():
    errors, cleaned = validate_transaction_payload()
    if errors:
        return jsonify({"error": errors}), 400
    global trasaction_id_counter
    if cleaned["transaction_type"] == "deposite":
        @app.route("/deposit", methods=["POST"])
        def deposite():
            data = request.get_json(silent=True)
            if data is None:
                return jsonify({"errors": "Request body must be valid JSON."}), 400
    
            errors, cleaned = validate_transaction_payload(data)
            if errors:
                return jsonify({"error": errors}), 400

            account_number = request.form["account_number"]
            amount = float(request.form['amount'])
    
            if account_number not in accounts:
                return jsonify({"error": f"Account not found."}), 404
            if amount <= 0:
                return jsonify({"error": "Invalid amount. Amount must be grater than 0."})

            deposite = {
                "transaction_type": cleaned["transaction_type"],
                "account_number": cleaned["account_number"],
                "amount": cleaned["amount"],
                "pin": cleaned["pin"],
                "message":"Deposite successful"
            }
            # accounts[account_number]['balance'] += {balance}
            return jsonify(deposite), 200
        
    elif cleaned["transaction_type"] == "withdrawl":
        @app.route("/withdrawl", methods=["POST"])
        def withdrawl():
            data = request.get_json(silent=True)
            if data is None:
                return jsonify({"errors": "Request body must be valid JSON."}), 400
    
            errors, cleaned = validate_transaction_payload(data)
            if errors:
                return jsonify({"error": errors}), 400
            
            account_number = request.form["account_number"]
            amount = float(request.form['amount'])
    
            if account_number not in accounts:
                return jsonify({"error": f"Account not found."}), 404
            if amount <= 0:
                return jsonify({"error": "Invalid amount. Amount must be grater than 0."})
            
            withdrawl = {
                "transaction_type": cleaned["transaction_type"],
                "account_number": cleaned["account_number"],
                "amount": cleaned["amount"],
                "pin": cleaned["pin"],
                "message":"withdrawl successful"
            }
            # accounts[account_number]['balance'] -= {balance}
            return jsonify(withdrawl), 200
































# ---------------------------------------------------------------------------
# ERROR HANDLERS — consistent JSON errors instead of Flask's default HTML
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed on this endpoint."}), 405


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "An internal server error occurred."}), 500






















if __name__ == "__main__":
    app.run(debug=True, port=5000)