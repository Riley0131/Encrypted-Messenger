import socket
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Configuration constants
USER_DB_FILE = 'users.json'
MSG_DB_FILE = 'stored_messages.json'
ITERATIONS = 100_000

# ---------- User management ----------

#pulls all of the created users from the database encrypted json file
def load_users():
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

#save a new user to the database
def save_users(users):
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f)

#create a new user with a username and password password is hashed and salted 
def register_user(username, password):
    users = load_users()
    #ensure that the username is not already taken
    if username in users:
        return False, 'User already exists'
    # Generate salt and hash password
    salt = os.urandom(16)
    # Use PBKDF2 with HMAC-SHA256 for password hashing
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    pw_hash = kdf.derive(password.encode('utf-8'))
    # Generate a per-user master key for message encryption
    master_key = Fernet.generate_key().decode('utf-8')
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'pw_hash': base64.b64encode(pw_hash).decode('utf-8'),
        'master_key': master_key
    }
    save_users(users)
    return True, 'User registered successfully'

#when a user logs in ensure that the user exists and the password is correct, entered password is hashed and salted to ensure secure transport
def verify_user(username, password):
    users = load_users()
    if username not in users:
        return False
    rec = users[username]
    salt = base64.b64decode(rec['salt'])
    stored_hash = base64.b64decode(rec['pw_hash'])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), stored_hash)
        return True
    except InvalidKey:
        return False

# Load the per-user Fernet object for encrypting/decrypting messages
def get_user_fernet(username):
    users = load_users()
    rec = users[username]
    # Load the raw master key (URL-safe base64)
    key = rec['master_key'].encode('utf-8')
    return Fernet(key)

# ---------- Message storage ----------


# Load and save the message database
def load_message_db():
    try:
        with open(MSG_DB_FILE, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return {}

#save the message to the encrypted database
def save_message_db(db):
    with open(MSG_DB_FILE, 'w') as f:
        json.dump(db, f)


# Store an encrypted message for a recipient
def store_encrypted_message(sender, recipient, token):
    db = load_message_db()
    db.setdefault(recipient, []).append({
        'from': sender,
        'token': token
    })
    save_message_db(db)


#pull messages from the database for a single user (recipient)
def retrieve_encrypted_messages(username):
    db = load_message_db()
    return db.get(username, [])

# ---------- Request handling ----------

# Handle incoming requests
def handle_request(req):
    action = req.get('action')
    username = req.get('username')

    # Registration (no auth required)
    if action == 'register':
        pw = req.get('password', '')
        if not username or not pw:
            return {'status': 'error', 'message': 'Username and password required'}
        success, msg = register_user(username, pw)
        return {'status': 'ok' if success else 'error', 'message': msg}

    # Other actions require auth
    if not username or 'password' not in req:
        return {'status': 'error', 'message': 'Username and password required'}
    pw = req['password']
    if not verify_user(username, pw):
        return {'status': 'error', 'message': 'Invalid credentials'}

    # At this point user is authenticated
    if action == 'send':
        recipient = req.get('to')
        msg = req.get('message', '')
        if not recipient:
            return {'status': 'error', 'message': '`to` (recipient) is required'}
        users = load_users()
        if recipient not in users:
            return {'status': 'error', 'message': 'Recipient not found'}
        # Encrypt under recipient's master key
        f_rec = get_user_fernet(recipient)
        token = f_rec.encrypt(msg.encode('utf-8')).decode('utf-8')
        store_encrypted_message(username, recipient, token)
        return {'status': 'ok', 'message': 'Message sent'}

    elif action == 'get':
        # Decrypt all messages addressed to this user
        f_user = get_user_fernet(username)
        inbox = retrieve_encrypted_messages(username)
        out = []
        for entry in inbox:
            try:
                pt = f_user.decrypt(entry['token'].encode('utf-8')).decode('utf-8')
            except Exception:
                pt = '[decryption error]'
            out.append({'from': entry['from'], 'message': pt})
        return {'status': 'ok', 'messages': out}

    return {'status': 'error', 'message': 'Unknown action'}

# ---------- Server loop ----------
def start_server(host='0.0.0.0', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    try:
        while True:
            client, addr = server_socket.accept()
            print(f"Connection from {addr}")
            data = client.recv(4096)
            if not data:
                client.close()
                continue
            try:
                req = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError:
                resp = {'status': 'error', 'message': 'Invalid JSON'}
            else:
                resp = handle_request(req)
            client.sendall(json.dumps(resp).encode('utf-8'))
            client.close()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server_socket.close()
        print("Socket closed. Goodbye.")

if __name__ == '__main__':
    start_server()
