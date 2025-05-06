from flask import Flask, render_template, request, redirect, url_for, session, flash
import client  # To import send_request in client.py
import json

app = Flask(__name__)
app.secret_key = 'secret-key'  # Replace this in production


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        req = {
            'action': 'register',
            'username': request.form['username'],
            'password': request.form['password']
        }
        response = client.send_request(req)
        if response.get('status') == 'ok':
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        else:
            flash(response.get('message'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        req = {
            'action': 'get',
            'username': request.form['username'],
            'password': request.form['password']
        }
        response = client.send_request(req)
        if response.get('status') == 'ok' or response.get('status') == 'ok':
            session['username'] = request.form['username']
            session['password'] = request.form['password']
            return redirect(url_for('inbox'))
        else:
            flash('Login failed: ' + response.get('message'))
    return render_template('login.html')


@app.route('/send', methods=['GET', 'POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        req = {
            'action': 'send',
            'username': session['username'],
            'password': session['password'],
            'to': request.form['to'],
            'message': request.form['message']
        }
        response = client.send_request(req)
        flash(response.get('message'))

    return render_template('send.html')


@app.route('/inbox')
def inbox():
    if 'username' not in session:
        return redirect(url_for('login'))

    req = {
        'action': 'get',
        'username': session['username'],
        'password': session['password']
    }
    response = client.send_request(req)
    messages = response.get('messages', []) if response.get('status') == 'ok' else []
    return render_template('inbox.html', messages=messages)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)