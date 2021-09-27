# pip install Flask
# pip install Flask-SQLAlchemy
# pip install pyJWT
# =====================================


from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

import os

basedir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SECRET_KEY'] = '321MySimpleSecret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, './dbTest.db')
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(80))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    user_role = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    expired_at = db.Column(db.DateTime)
    admin = db.Column(db.Boolean, default=False)




def complete_data(in_data, parameters):
    for field in parameters:
        if not in_data.get(field):
            return False
    return True
#
# if not complete_data(data, ['first_name', 'last_name', 'email', 'password']):
#     return jsonify(dict(message='Incorrect input data!'))


def token_required(func):
    @wraps(func)
    def decorated(*args, **kvargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return func(current_user, *args, **kvargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['public_id'] = user.public_id
        user_data['first_name'] = user.first_name
        user_data['last_name'] = user.last_name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['user_role'] = user.user_role
        user_data['created_at'] = user.created_at
        user_data['updated_at'] = user.updated_at
        user_data['expired_at'] = user.expired_at

        output.append(user_data)

    return jsonify(dict(users=output))


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['id'] = user.id
    user_data['public_id'] = user.public_id
    user_data['first_name'] = user.first_name
    user_data['last_name'] = user.last_name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['user_role'] = user.user_role
    user_data['created_at'] = user.created_at
    user_data['updated_at'] = user.updated_at
    user_data['expired_at'] = user.expired_at

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    expired_date = datetime.now() + timedelta(days=30)
    new_user = User(public_id=str(uuid.uuid4()),
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                    email=data['email'],
                    password=hashed_password,
                    expired_at=expired_date)

    db.session.add(new_user)
    db.session.commit()
    return jsonify(dict(message='New user CREATED.'))


@app.route('/user/<public_id>/email/<update_data>', methods=['PUT'])
@token_required
def update_user(current_user, public_id, update_data):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found!'})

    user.email = update_data
    print(update_data)
    db.session.commit()
    return jsonify({'message': 'User has been updated', 'email': str(update_data)})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found!'})

    db.session.delete(user)
    db.session.commit()
    return 'From Delete user'


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Autenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(first_name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Autenticate': 'Basic realm="Login required!"'})

    expired_at = datetime.now() + timedelta(minutes=30)
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': expired_at}, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Autenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
