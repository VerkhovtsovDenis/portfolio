from backend import valid_login

from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData, Table, Column, Integer, ARRAY


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URL'] = 'postgres://postgres:123@localhost/py_swear'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)
    admin_access = db.Column(db.Boolean, nullable=False)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=False, nullable=False)
    description = db.Column(db.String(1000), unique=False, nullable=True)
    date_start = db.Column(db.Date, unique=False, nullable=True)
    date_end = db.Column(db.Date, unique=False, nullable=True)


db.create_all()

@app.route('/')
def hello_world(error = None):
    return render_template('index.html', error=error)

@app.route('/main')
def main():
    return 'main!'

@app.route('/user/<username>')
def profile(username):
    return f'{username}\'s profile'

@app.route('/sing_in', methods=['POST','GET'])
def sing_in():
    error = None
    if request.method == 'POST':
        if valid_login(request.form['username'],
                       request.form['password']):
            return redirect(url_for('profile', username=request.form['username'], users=db.Users))
        else:
            print('Deny')
            error = 'Invalide username/password'
        print('-> Deny')
    return render_template('index.html', error=error)


with app.test_request_context():
    print(url_for('hello_world'))
    print(url_for('main'))
    print(url_for('profile', username='John Doe'))
