# ==== #
# Libs #
# ==== #

import os

from flask import Flask, request, make_response, redirect, abort
from flask_sqlalchemy import SQLAlchemy

# ====== #
# Config #
# ====== #

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    FLASK_APP = 'server',
)

db = SQLAlchemy(app)
debug = True

# ===== #
# Model #
# ===== #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(140), unique=True, nullable=False)
    email = db.Column(db.String(140), unique=True, nullable=False)
    password = db.Column(db.String(140), nullable=False)

with app.app_context():
    db.create_all()

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
    return User.query.filter_by(id=request.cookies.get('user_id')).first()

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

    db.session.add(User(
        username=request.form['username'],
        email=request.form['email'],
        password=request.form['password']
    ))
    db.session.commit()
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
    for field in request.form.keys():
        if not request.form[field]:
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    registered_user = User.query.filter_by(
        email=request.form['email'],
        password=request.form['password']
    ).first()

    if registered_user:
        res = make_response(redirect('/profile'), 302)
        res.set_cookie('user_id', str(registered_user.id))
        return res

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
    res.set_cookie('user_id', '', max_age=0)
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
