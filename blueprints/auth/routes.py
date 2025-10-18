from flask import request, Blueprint, redirect, url_for
from flask_jwt_extended import create_access_token, get_jwt_identity, create_refresh_token, jwt_required
from blueprints.auth.models import JWT, User, AuthEntry
from extensions.db import db
from extensions.bcrypt import bcrypt
from extensions.mail import mail
import uuid
import secrets
from flask_mail import Message
from datetime import timedelta, datetime, timezone
import json as jn

auth_bl = Blueprint('auth_bl', __name__)

@auth_bl.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    rftk = data.get('rftk')
    step = request.args.get('step')

    if step == 'first_entry':

        user = User.query.filter_by(username=username).first()
        if not user:
            return {'message': 'user not found'}, 404
        elif not bcrypt.check_password_hash(user.password, password):
            return {'message': 'password is invalid'}, 401
        
        entry_id = uuid.uuid4()
        auth_code = str(secrets.randbelow(1000000)).zfill(6)
        auth_entry = AuthEntry(id=str(entry_id), code=auth_code, user_id=user.id, expires_date=datetime.now(timezone.utc) + timedelta(minutes=5))

        try:
            mail_msg = Message(subject='Verification code from <company name>', body=f'Hi {user.username}, this is a verification code that you should type in the app:', html=f'<h2>{auth_code}</h2>', recipients=[user.email])
            mail.send(mail_msg)
        except Exception as e:
            return {'message': f'Oops, something went wrong on our end. : {e}'}, 500


        db.session.add(auth_entry)
        db.session.commit()

        return {'message': 'redirect to verify page on frontend', 'user_id': f'{user.id}', 'user_email': f'{user.email}', 'user_password': f'{password}'}, 200
        
    


    # Refresh Token proccess at login

    if not step == 'jwt':
        return {'message': 'Unauthorized'}, 401
    
    json_load_string = request.args.get('json_load')
    json_data = jn.loads(json_load_string)
    username_from_verify = json_data.get('username')
    password_from_verify = json_data.get('password')
    
    user_at_jwt_step = User.query.filter_by(username=username_from_verify).first()
    if not user_at_jwt_step:
        return {"message": "user not found"}, 404

    # Step skipped detection

    if not user_at_jwt_step.passed_code_check:
        return {'message': 'Step skipped, redirect to login'}, 401



    user_jwt_tables = JWT.query.filter_by(user_id=user_at_jwt_step.id)
    db.session.delete(user_jwt_tables)
    db.session.commit()

    
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    new_rftk = JWT(rftk=refresh_token, user_id=user_at_jwt_step.id, user_name=user_at_jwt_step.username)
    
    
    db.session.add(new_rftk)
    db.session.commit()

    return {'actk': access_token, 'rftk': refresh_token}, 200

@auth_bl.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = uuid.uuid4()
    username = data.get('username')
    password = bcrypt.generate_password_hash(data.get('password'))
    email = data.get('email')
    job = data.get('job') if data.get('job') else 'not provided'

    if not username and password and email:
        return {'message': 'please fill all the fields'}, 401

    new_user = User(id=str(user_id), username=username, password=password, avatar='none', email=email, job=job, passed_code_check=False)
    db.session.add(new_user)
    db.session.commit()

    return {'message': 'success'}, 200

@auth_bl.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    rftk_header = request.headers.get('Authorization')
    rftk = rftk_header.split(" ")[1]
    current_user_name = get_jwt_identity()

    current_user_jwt_database = JWT.query.filter_by(user_name=current_user_name)
    current_rftk = current_user_jwt_database.filter(JWT.rftk==rftk).first()


    # Reuse detected
    if not current_rftk:
        hacked_user_jwt_database = JWT.query.filter_by(rftk=rftk).first()
        if not hacked_user_jwt_database:
            return {'message': 'refresh token is not found'}, 404
        else:

            db.session.delete(hacked_user_jwt_database)
            db.session.commit()

            return {'message': 'refresh token is not found'}, 404
    
    db.session.delete(current_rftk)
    db.session.commit()
    
    new_access_token = create_access_token(identity=current_user_name)
    new_refresh_token = create_refresh_token(identity=current_user_name)

    current_user = User.query.filter_by(username=current_user_name).first()

    db.session.add(JWT(rftk=new_refresh_token, user_id=current_user.id, user_name=current_user_name))
    db.session.commit()

    return {'rftk': new_refresh_token, 'actk': new_access_token}, 200

@auth_bl.route('/verify', methods=['POST'])
def verify():
    json = request.get_json()
    code = json.get('code')
    user_id = json.get('user_id')
    user_password = json.get('user_password')

    auth_entry = AuthEntry.query.filter_by(user_id=user_id, code=code).first()
    user = User.query.filter_by(id=user_id).first()

    if not auth_entry:
        return {'message': 'Invalid auth code'}, 401
    
    if auth_entry.expires_date < datetime.now(timezone.utc):
        return {'message': 'The auth code has been expired'}, 401
    
    user.passed_code_check = True
    
    db.session.delete(auth_entry)
    db.session.commit()

    return redirect(url_for('auth.login'), step='jwt', json_load=jn.dumps({"username": user.username, "password": user_password}))


@auth_bl.route('/protected', methods=['POST'])
@jwt_required()
def protected():
    return {'message': 'this is a protected route, made some chages to the docker container'}

@auth_bl.route('/user_data_auth_to_taskservice', methods=['GET'])
@jwt_required()
def data():
    username = get_jwt_identity()
    current_user = User.query.filter_by(username=username).first()
    if not current_user:
        return {'message': 'user not found'}, 401
    
    current_user_data = current_user.to_dict()
    
    return current_user_data, 200

    





    
        