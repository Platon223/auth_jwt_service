from flask import request, Blueprint, redirect, url_for, current_app, jsonify
from flask_jwt_extended import create_access_token, get_jwt_identity, create_refresh_token, jwt_required
from blueprints.auth.models import JWT, User, AuthEntry, ForgotPasswordEntry
from extensions.db import db
from extensions.bcrypt import bcrypt
from extensions.mail import mail
import uuid
import secrets
from flask_mail import Message
from datetime import timedelta, datetime, timezone
import json as jn
from extensions.oauth import oauth, github
import os
from dotenv import load_dotenv
import requests
from validates.login import validate_login

load_dotenv()

auth_bl = Blueprint('auth_bl', __name__)

@auth_bl.route('/login', methods=['POST'])
def login():
    data = validate_login(request)
    if "error" in data:
        return {"message": data}, 400
    username = data.get('username')
    password = data.get('password')
    remember_me = data.get('remember')
    step = request.args.get('step')

    if step == 'first_entry':

        user = User.query.filter_by(username=username).first()
        if not user:
            return {'message': 'user not found'}, 404
        elif not bcrypt.check_password_hash(user.password, password):
            return {'message': 'password is invalid'}, 401
        
        if not user.remember or user.remember_me_expire_date.timestamp() < datetime.now(timezone.utc).timestamp():
            if user.remember_me_expire_date and user.remember_me_expire_date.timestamp() < datetime.now(timezone.utc).timestamp():
                user.remember = False
                user.remember_me_expire_date = None
                db.session.commit()

            entry_id = uuid.uuid4()
            auth_code = str(secrets.randbelow(1000000)).zfill(6)
            auth_entry = AuthEntry(id=str(entry_id), code=auth_code, user_id=user.id, expires_date=datetime.now(timezone.utc) + timedelta(minutes=5))

            try:
                mail_msg = Message(subject='Your verification code is: ', body=f'Hi {user.username}, this is a verification code that you should type in the app:', html=f'<h2>{auth_code}</h2>', recipients=[user.email])
                mail.send(mail_msg)
            except Exception as e:
                return {'message': f'Oops, something went wrong on our end. : {e}'}, 500
            

            db.session.add(auth_entry)
            db.session.commit()

            return {'message': 'redirect to verify page on frontend', 'user_id': f'{user.id}', 'user_email': f'{user.email}', 'user_password': f'{password}', 'user_remembered': remember_me if remember_me != None else False}, 200
        else:
            step = 'jwt'

        


    # Refresh Token proccess at login

    if not step == 'jwt':
        return {'message': 'Unauthorized'}, 401

    
    user_at_jwt_step = User.query.filter_by(username=username).first()
    if not user_at_jwt_step:
        return {"message": "user not found"}, 404

    # Step skipped detection

    if not user_at_jwt_step.passed_code_check:
        return {'message': 'Step skipped, redirect to login'}, 401



    user_jwt_tables = JWT.query.filter_by(user_id=user_at_jwt_step.id)
    user_jwt_tables.delete()
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

    new_user = User(id=str(user_id), username=username, password=password, avatar='none', email=email, job=job, passed_code_check=False, has_perm_to_change_passwrd=False, remember = False)
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
    remember = json.get('remember')
    for_type = request.args.get('type')

    if for_type == 'password':

        forgot_password_entry = ForgotPasswordEntry.query.filter_by(user_id=user_id, code=code).first()
        user = User.query.filter_by(id=user_id).first()

        if not forgot_password_entry:
            return {'message': 'Invalid recreation code'}, 401
        
        timestamp_fp_expires_date = forgot_password_entry.expires_date.timestamp()
        timestamp_fp_real_time = datetime.now(timezone.utc).timestamp()

        if timestamp_fp_expires_date < timestamp_fp_real_time:
            db.session.delete(forgot_password_entry)
            db.session.commit()
            return {'message': 'The recreation code has been expired'}, 401
        
        user.has_perm_to_change_passwrd = True
        
        db.session.delete(forgot_password_entry)
        db.session.commit()

        return {'message': 'redirect to create new password page on frontend', 'user_id': user_id}, 200
    

    auth_entry = AuthEntry.query.filter_by(user_id=user_id, code=code).first()
    user = User.query.filter_by(id=user_id).first()

    if not auth_entry:
        return {'message': 'Invalid auth code'}, 401
    
    timestamp_expires_date = auth_entry.expires_date.timestamp()
    timestamp_real_time = datetime.now(timezone.utc).timestamp()
    
    if timestamp_expires_date < timestamp_real_time:
        db.session.delete(auth_entry)
        db.session.commit()
        return {'message': 'The auth code has been expired'}, 401
    
    user.passed_code_check = True
    if remember:
        user.remember = True
        # For testing purposes the expiration date of remember me is going to be 2 min
        user.remember_me_expire_date = datetime.now(timezone.utc) + timedelta(minutes=2)
    
    db.session.delete(auth_entry)
    db.session.commit()

    with current_app.test_client() as client:
        response = client.post(
            '/auth/login?step=jwt',
            json={"username": user.username, "password": user_password}
        )
        
        return jsonify(response.get_json()), response.status_code
    

@auth_bl.route('/forgot_password', methods=['POST'])
def forgot_password():
    json = request.get_json()
    email = json.get('email')

    user = User.query.filter_by(email=email).first()

    if not user:
        return {'message': 'user not found'}, 401
    
    code_id = uuid.uuid4()
    forgot_password_code = str(secrets.randbelow(1000000)).zfill(6)
    password_code_entry = ForgotPasswordEntry(id=str(code_id), code=forgot_password_code, user_id=user.id, expires_date=datetime.now(timezone.utc) + timedelta(minutes=10))

    try:
        mail_msg = Message(subject='Your password recreation code is: ', body=f'Hi there, this is a verification code that you should type in the app, to change your password:', html=f'<h2>{forgot_password_code}</h2>', recipients=[email])
        mail.send(mail_msg)
    except Exception as e:
        return {'message': f'Oops, something went wrong on our end. : {e}'}, 500


    db.session.add(password_code_entry)
    db.session.commit()

    return {'message': 'verify page to create a new password on frontend', 'user_id': user.id}, 200

@auth_bl.route('/oauth', methods=['POST'])
def oauth():
    json = request.get_json()
    provider = json.get('provider')
    authorize_redirect = f'http://localhost:5555/auth/oauth_authorize/{provider}'
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={os.getenv('GITHUB_OAUTH_CLIENT_ID')}&redirect_uri={authorize_redirect}&scope=user:email"

    return {'redirect': redirect_uri}, 200


@auth_bl.route('/oauth_authorize/<provider>', methods=['GET'])
def authorize(provider):

    code = request.args.get('code')
    if not code:
        return {'message': 'no authorization code'}, 400
    
    access_token_request = "https://github.com/login/oauth/access_token"
    body = {
        "client_id": os.getenv("GITHUB_OAUTH_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
        "code": code
    }
    headers = {"Accept": "application/json"}
    response = requests.post(access_token_request, data=body, headers=headers)
    token = response.json()

    access_token = token.get("access_token")
    if not access_token:
        return {"message": "failed to obtain an access token"}, 400
    
    user_data = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {access_token}"}
    ).json()

    user_emails = requests.get(
        "https://api.github.com/user/emails",
        headers={"Authorization": f"token {access_token}"}
    ).json()
        

    for e in user_emails:
        if e.get('primary'):
            email = e.get('email')
            break

    user = User.query.filter_by(id=str(user_data['id'])).first()

    if not user:
        new_user = User(
            id=str(user_data['id']), 
            username=user_data['login'], 
            password='github_provider', 
            avatar='none', 
            email=email, 
            job='github_provider', 
            passed_code_check=False, 
            has_perm_to_change_passwrd=False, 
            remember = False,
            provider = 'github'
        )

        # Github OAuth doesn't provide refresh tokens

        if provider == 'github':
            return {'actk': access_token}

        new_rftk = JWT(
            rftk = token.get('refresh_token'),
            user_id = str(user_data['id']),
            user_name = user_data['login']
        )

        db.session.add(new_user)
        db.session.add(new_rftk)
        db.session.commit()

        return {'actk': token.get('access_token'), 'rftk': token.get('refresh_token')}
    
    if provider == 'github':
        return {'actk': access_token}
    
    user_jwt_tables = JWT.query.filter_by(user_id=str(user_data['id']))
    user_jwt_tables.delete()
    db.session.commit()

    new_access_token = token.get('access_token')
    new_refresh_token = token.get('refresh_token')

    new_rftk = JWT(
        rftk = new_refresh_token,
        user_id = str(user_data['id']),
        user_name = user_data['login']
    )

    db.session.add(new_rftk)
    db.session.commit()

    return {'actk': new_access_token, 'rftk': new_refresh_token}



@auth_bl.route('/new_password', methods=['POST'])
def generate_new_password():
    json = request.get_json()
    user_id = json.get('user_id')
    new_password = bcrypt.generate_password_hash(data.get('password'))


    user = User.query.filter_by(id=user_id).first()

    if not user:
        return {'message': 'user not found'}, 404
    
    if not user.has_perm_to_change_passwrd:
        return {'message': 'user not verified'}, 401
    
    user.password = new_password
    db.session.commit()

    return {'message': 'password changed successfuly, redirect to login'}, 200



@auth_bl.route("/find_by_username", methods=["GET"])
@jwt_required()
def find_user():
    username = get_jwt_identity()
    current_user = User.query.filter_by(username=username).first()
    if not current_user:
        return {'message': 'user not found'}, 401

    return current_user.id, 200
    

    





    
        