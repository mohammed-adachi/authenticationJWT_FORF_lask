import jwt
from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps
app = Flask(__name__, template_folder='monenv/templates')

app.config['SECRET_KEY']='572a60ee0a79417095e9b693927af0c9'
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return "Hello Boss!"
@app.route('/login', methods=['POST'])
def do_admin_login():
    if request.form['password'] == 'password' and request.form['username'] == 'admin':
        session['logged_in'] = True
        jwt_token = jwt.encode({'user': request.form['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': jwt_token.decode('UTF-8')})
    else:
        return 'wrong password!'
@app.route('/auth')
@token_required
def auth():
    return 'Hello Boss!'
if __name__ == '__main__':
    app.run(debug=True)

    