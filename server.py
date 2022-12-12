# ==== #
# Libs #
# ==== #

import os
import json
import requests

from hashlib import md5
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

from flask import Flask, request, make_response, redirect, abort
from flask_sqlalchemy import SQLAlchemy

# ====== #
# Config #
# ====== #

# App & DB

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    FLASK_APP = 'server',
)

db = SQLAlchemy(app)
debug = True

SALT_SIZE = 16
SESSION_ID_SIZE = 16
KEY_SIZE = 16

# ===== #
# Model #
# ===== #

class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email    = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

class Session(db.Model):
    id         = db.Column(db.String, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

with app.app_context():
    db.create_all()

# ============ #
# Cryptography #
# ============ #

class HMAC:
    def __init__(self, mac=None):
        self.mac = os.urandom(KEY_SIZE) if mac is None else mac
        self.hmac = hmac.HMAC(self.mac, hashes.SHA256())

    def execute(self, message, finalize=True):
        self.hmac.update(message)
        if finalize:
            return self.hmac.finalize()

    def verify(self, signature):
        self.hmac.verify(signature)

class AES:
    def __init__(self, key, iv):
        self.key = os.urandom(KEY_SIZE) if key is None else key
        self.iv = os.urandom(KEY_SIZE) if iv is None else iv

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(self.iv),
            backend=default_backend()
        )

        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message):
        return self.encryptor.update(message) + self.encryptor.finalize()

    def decrypt(self, message):
        return self.decryptor.update(message) + self.decryptor.finalize()

class KeySerializer:
    def __init__(self, public_key_path, private_key_path=None):
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path

    def _read_public(self):
        with open(self.public_key_path, "rb") as public_key_file_object:
            public_key = serialization.load_pem_public_key(
                public_key_file_object.read(),
                backend=default_backend()
            )
        return public_key

    def _read_private(self):
        with open(self.private_key_path, "rb") as private_key_file_object:
            private_key = serialization.load_pem_private_key(
                private_key_file_object.read(),
                backend=default_backend(),
                password=None
            )
        return private_key

    def read(self, which):
        readers = {
            'public' : self._read_public,
            'private' : self._read_private,
        }
        return readers[which]()

class Transmission:
    def __init__(
            self,
            server_public_key,
            server_private_key=None,
            aes_key=None,
            mac=None,
            iv=None,
        ):
        self.server_public_key = server_public_key
        self.server_private_key = server_private_key

        self.aes = AES(key=aes_key, iv=iv)
        self.sym_hmac = HMAC(
            mac=self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self.assym_hmac = HMAC(mac=mac)

    def send(self, message_bytes):
        sym_keys = self.aes.key + self.aes.iv + self.assym_hmac.mac

        session_keys = self.server_public_key.encrypt(
            sym_keys,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cyphertext = self.aes.encrypt(message_bytes)
        signature = self.assym_hmac.execute(session_keys + cyphertext)

        payload = {
            'session_keys': bytearr_to_b64(session_keys),
            'cyphertext'  : bytearr_to_b64(cyphertext),
            'hmac'        : bytearr_to_b64(signature),
        }

        print('\nConteúdo da requisição:')
        print(payload)

        return requests.post(
            'http://localhost:5000/signin',
            headers={ 'Content-Type': 'application/octet-stream' },
            data=json.dumps(payload).encode('utf-8')
        )

    def verify(self, received_bytes):
        session_keys = received_bytes['session_keys']
        cyphertext = received_bytes['cyphertext']
        signature = received_bytes['hmac']

        self.assym_hmac.execute(session_keys + cyphertext, finalize=False)
        self.assym_hmac.verify(signature)
        return

    def receive(self, cyphertext):
        return json.loads(self.aes.decrypt(cyphertext).decode('utf-8'))

# ===== #
# Utils #
# ===== #

def get_header(title):
    return (
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
        </head>
        """
    )

def get_user_from_cookies():
    curr_session_id = request.cookies.get('session_id')

    if curr_session_id:
        curr_session = Session.query.filter_by(id=curr_session_id).first()
        user = User.query.filter_by(id=curr_session.user_id).first()

        user_last_session = Session.query.filter_by(user_id=user.id)          \
                                         .order_by(Session.created_at.desc()) \
                                         .first()

        if user_last_session.id == curr_session_id:
            return user
    return

def bytearr_to_b64(bytearr):
    return b64encode(bytearr).decode('utf-8')

def b64_to_bytearr(b64):
    return b64decode(b64.encode('utf-8'))

def is_correct_password(kdf, password_bytes, digest):
    try:
        kdf.verify(password_bytes, digest)
        return True
    except InvalidKey:
        return False

def create_session(user_id):
    session_id = bytearr_to_b64(md5(os.urandom(SESSION_ID_SIZE)).digest())

    db.session.add(
        Session(
            id=session_id,
            user_id=user_id
        )
    )
    db.session.commit()

    res = make_response(redirect('/profile'), 302)
    res.set_cookie('session_id', session_id)

    print('\nUsuário logado:')
    print('ID da sessão:', session_id, end='\n\n')
    return res

def init_kdf(salt=None):
    if salt is None: salt = os.urandom(SALT_SIZE)
    return (
        Scrypt(
            salt=salt, # Secret
            length=32, # Derived key desired length
            n=2**14,   # CPU and Memory cost parameter
            r=8,       # Blocksize parameter
            p=1,       # Parallelization parameter
            backend=default_backend()
        ), salt
    )

def decrypt_session_keys(cipher_keys, server_private_key):
    session_keys = server_private_key.decrypt(
        cipher_keys,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aes_key = session_keys[: KEY_SIZE]
    aes_iv = session_keys[KEY_SIZE : 2*KEY_SIZE]
    assym_mac = session_keys[2*KEY_SIZE :]
    return aes_key, aes_iv, assym_mac


# =========== #
# Controllers #
# =========== #

def get_homepage():
    return make_response(
        get_header('EP4 | Redes') +
        """
        <body>
            <h1>EP4 de Redes</h1>
            <h2>Criptografia</h2>
            <ul>
                <li><a href="signup">Sign Up</a></li>
                <li><a href="signin">Sign In</a></li>
            </ul>
        </body>
        """, 200
    )

def get_signup():
    return make_response(
        get_header('EP4 | Sign Up') +
        """
        <body>
            <h1>Sign Up</h1>
            <form action="/signup" method="post" />
                <input name="username" id="username" placeholder="Username*" type="text" />
                <br />
                <input name="email" id="email" placeholder="E-mail*" type="email" />
                <br />
                <input name="password" id="password" placeholder="Password*" type="password" />
                <br />
                <br />
                <input id="submit" type="submit" value="Sign Up" />
            </form>
            <br />
            <a href="/">< Back</a>
        </body>
        """, 200
    )

def post_signup():
    for field in request.form.keys():
        if not request.form[field]:
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    same_username_user = User.query.filter_by(username=request.form['username']).first()
    same_email_user = User.query.filter_by(email=request.form['email']).first()
    if same_username_user or same_email_user:
        return make_response('User already exists!', 400)

    kdf, salt = init_kdf()
    digest = kdf.derive(request.form['password'].encode('utf-8'))

    db.session.add(User(
        username=request.form['username'],
        email=request.form['email'],
        password=bytearr_to_b64(salt + digest)
    ))
    db.session.commit()

    print('\nUsuário cadastrado:')
    print('i)   Senha original:', request.form['password'])
    print('ii)  Sal:', salt.hex(), '| Digest:', digest.hex())
    print('iii) Salvo no banco:', bytearr_to_b64(salt + digest), end='\n\n')
    return make_response('User created!', 201)

def get_signin():
    return make_response(
        get_header('EP4 | Sign In') +
        """
        <body>
            <h1>Sign In</h1>
            <form action="/signin" method="post" />
                <input name="email" id="email" placeholder="E-mail*" type="email" />
                <br />
                <input name="password" id="password" placeholder="Password*" type="password" />
                <br />
                <br />
                <input id="submit" type="submit" value="Sign In" />
            </form>
            <br />
            <a href="/">< Back</a>
        </body>
        """, 200
    )

def post_signin():
    data = json.loads(request.data.decode('utf-8'))
    for key, val in data.items():
        data[key] = b64_to_bytearr(val)

    key_serializer = KeySerializer(
        public_key_path='./keys/rsa.public.pem',
        private_key_path='./keys/rsa.private.pem',
    )
    server_public_key = key_serializer.read('public')
    server_private_key = key_serializer.read('private')

    aes_key, aes_iv, assym_mac = decrypt_session_keys(
        data['session_keys'],
        server_private_key
    )

    transmission = Transmission(
        server_public_key=server_public_key,
        server_private_key=server_private_key,
        aes_key=aes_key,
        iv=aes_iv,
        mac=assym_mac
    )
    transmission.verify(data)
    credentials = transmission.receive(data['cyphertext'])

    for field in credentials.keys():
        if not credentials[field]:
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    registered_user = User.query.filter_by(
        email=credentials['email'],
    ).first()

    if registered_user:
        stored_hash_bytes = b64_to_bytearr(registered_user.password)
        stored_salt = stored_hash_bytes[:SALT_SIZE]
        stored_digest = stored_hash_bytes[SALT_SIZE:]
        sent_password_bytes = credentials['password'].encode('utf-8')

        kdf, _ = init_kdf(stored_salt)

        if is_correct_password(kdf, sent_password_bytes, stored_digest):
            return create_session(str(registered_user.id))
    return make_response('User not found!', 401)

def get_profile():
    logged_user = get_user_from_cookies()

    if logged_user:
        return make_response(
            get_header('EP4 | Profile') +
            f"""
            <body>
                <h1>Profile</h1>
                <p>Signed in as: <b>{logged_user.username}</b></p>
                <ul>
                    <li><a href="/">Home</a></li>
                    <li><a href="/logout">Logout</a></li>
                </ul>
            </body>
            """, 200
        )
    return abort(401, description="User not logged in!")

def get_logout():
    logged_user = get_user_from_cookies()

    if logged_user:
        return make_response(
            get_header('EP4 | Logout') +
            f"""
            <body>
                <h1>Logout</h1>
                <p>Signed in as: <b>{logged_user.username}</b></p>
                <p>Do you really want to logout?</p>
                <div style="display: flex">
                    <form action="/profile" method="get">
                        <input type="submit" href="/profile" value="Back" />
                    </form>
                    <form action="/logout" method="post">
                        <input type="submit" href="/logout" value="Logout" />
                    </form>
                </div>

            </body>
            """, 200
        )
    return abort(401, description="User not logged in!")

def post_logout():
    res = make_response(redirect('/'), 302)
    res.set_cookie('session_id', '', max_age=0)
    return res

# ====== #
# Routes #
# ====== #

@app.route('/')
def get_landpage():
    return get_homepage()

@app.route('/signup', methods =['GET', 'POST'])
def handle_signup():
    if request.method == 'GET': return get_signup()
    if request.method == 'POST': return post_signup()
    return make_response(f"Can't {request.method} /signup", 405)

@app.route('/signin', methods =['GET', 'POST'])
def handle_signin():
    if request.method == 'GET': return get_signin()
    if request.method == 'POST': return post_signin()
    return make_response(f"Can't {request.method} /signin", 405)

@app.route('/profile')
def get_user():
    return get_profile()

@app.route('/logout', methods =['GET', 'POST'])
def handle_logout():
    if request.method == 'GET': return get_logout()
    if request.method == 'POST': return post_logout()
    return make_response(f"Can't {request.method} /logout", 405)

# ===== #
# Start #
# ===== #

app.run(debug=debug)
