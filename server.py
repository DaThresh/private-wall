from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
from mysql import connectMySQL
from datetime import datetime
import math
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = 'this is a secret'
bcrypt = Bcrypt(app)

@app.route("/")
def home():
    register_data = {
        'email': '',
        'first_name': '',
        'last_name': ''
    }
    if 'register_data' in session:
        register_data = session['register_data']
        session.pop('register_data')
    return render_template("index.html", rd=register_data)

@app.route("/wall")
def wall():
    if not 'id' in session:
        flash("You must be logged in to view your wall")
        return redirect("/")
    # get all the users
    db = connectMySQL('private_wall')
    query = "SELECT id, first_name FROM users WHERE id != %(id)s ORDER BY users.first_name ASC"
    data = {
        'id': session['id']
    }
    people = db.query_db(query, data)
    # get # of sent messages
    db = connectMySQL('private_wall')
    query = "SELECT COUNT(users.id) AS total FROM users JOIN messages ON users.id = messages.sender_id WHERE users.id = %(id)s"
    data = {
        'id': int(session['id'])
    }
    result = db.query_db(query, data)
    num_messages_sent = result[0]['total']
    # get all the messages
    db = connectMySQL('private_wall')
    query = "SELECT UNIX_TIMESTAMP(messages.created_at) AS time, t3.first_name as sender_name, messages.content as message, messages.id AS msg_id FROM users JOIN messages on users.id = messages.receiver_id JOIN users as t3 ON t3.id = messages.sender_id WHERE users.id = %(r_id)s"
    data = {
        'r_id': int(session['id'])
    }
    messages = db.query_db(query, data)
    num_messages_received = len(messages)
    for message in messages:
        now = math.floor(datetime.now().timestamp())
        diff = now - message['time']
        message['time'] = f"{diff} seconds ago"
        if diff >= 60:
            message['time'] = f"{math.floor(diff / 60)} minute(s) ago"
        if diff >= 3600:
            message['time'] = f"{math.floor(diff / 3600)} hour(s) ago"
        if diff >= 86400:
            message['time'] = f"{math.floor(diff / 86400)} day(s) ago"
        if diff >= 2592000:
            message['time'] = f"{math.floor(diff / 2592000)} month(s) ago"
    return render_template("wall.html", people=people, msgs=messages, num_messages_received=num_messages_received, num_messages_sent=num_messages_sent)

@app.route("/sendmsg", methods=['POST'])
def sendmsg():
    if 'id' in session:
        is_valid = True
        if len(request.form['msg']) < 5:
            is_valid = False
            flash("Message must be at least 5 characters long")
        if is_valid:
            db = connectMySQL('private_wall')
            query = "INSERT INTO messages (sender_id, receiver_id, content) VALUES (%(s_id)s, %(r_id)s, %(msg)s)"
            data = {
                's_id': int(session['id']),
                'r_id': int(request.form['id']),
                'msg': request.form['msg']
            }
            db.query_db(query, data)
            flash("Sent message!")
        return redirect("/wall")
    return redirect("/")

@app.route("/delete/<id>")
def delete(id):
    if 'id' in session:
        db = connectMySQL('private_wall')
        query = "SELECT * FROM messages WHERE messages.id = %(id)s"
        data = {
            'id': int(id)
        }
        result = db.query_db(query, data)
        if result[0]['receiver_id'] == session['id']:
            db = connectMySQL('private_wall')
            query = "DELETE FROM messages WHERE messages.id = %(id)s"
            data = {
                'id': int(id)
            }
            db.query_db(query, data)
            flash("Successfully deleted message")
            return redirect("/wall")
    flash(f"{id}")
    return redirect("/danger")

@app.route("/danger")
def danger():
    ip = request.environ['REMOTE_ADDR']
    return render_template("danger.html", ip=ip)

@app.route("/register", methods=['POST'])
def register():
    if 'id' in session:
        flash("Already logged in")
        return redirect("/")
    is_valid = True
    if len(request.form['register_first_name']) < 2:
        is_valid = False
        flash("First name must be at minimum 2 characters")
    if len(request.form['register_last_name']) < 2:
        is_valid = False
        flash("Last name must be at minimum 2 characters")
    if not EMAIL_REGEX.match(request.form['register_email']):
        is_valid = False
        flash("Not a valid email")
    if len(request.form['register_password']) < 8:
        is_valid = False
        flash("Password must be at least 8 characters long")
    if request.form['register_password'] != request.form['register_cpassword']:
        is_valid = False
        flash("Passwords do not match")
    if is_valid:
        db = connectMySQL('private_wall')
        query = "SELECT email FROM users WHERE email = %(em)s"
        data = {
            'em': request.form['register_email']
        }
        result = db.query_db(query, data)
        if result:
            flash("Email already signed up")
        else:
            db = connectMySQL('private_wall')
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s)"
            data = {
                'fn': request.form['register_first_name'],
                'ln': request.form['register_last_name'],
                'em': request.form['register_email'],
                'pw': bcrypt.generate_password_hash(request.form['register_password'])
            }
            id = db.query_db(query, data)
            session['id'] = id
            session['fn'] = request.form['register_first_name'].capitalize()
            flash("Logged in successfully")
            return redirect("/wall")
    session['register_data'] = {
        'first_name': request.form['register_first_name'],
        'last_name': request.form['register_last_name'],
        'email': request.form['register_email']
    }
    return redirect("/")
            # no record in DB matches email entered to register

@app.route("/login", methods=['POST'])
def login():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['login_email']):
        is_valid = False
    if len(request.form['login_password']) < 8:
        is_valid = False
    if 'id' in session:
        flash("Already logged in")
        return redirect("/")
    if not is_valid:
        flash("Unable to login")
    else:
        db = connectMySQL('private_wall')
        query = "SELECT id, first_name, password FROM users WHERE email LIKE %(em)s"
        data = {
            'em': request.form['login_email']
        }
        result = db.query_db(query, data)
        if result:
            if bcrypt.check_password_hash(result[0]['password'], request.form['login_password']):
                session['id'] = int(result[0]['id'])
                session['fn'] = result[0]['first_name']
                flash("Successfully logged in")
                return redirect("/wall")
            else:
                flash("Unable to login")
        else:
            flash("Unable to login")
    return redirect("/")

@app.route("/logout")
def logout():
    if 'id' in session:
        session.clear()
        flash("Logged out")
    else:
        flash("Not logged in")
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)