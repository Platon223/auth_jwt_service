from flask import request, Blueprint
from flask_jwt_extended import create_access_token, get_jwt_identity, create_refresh_token, jwt_required
from blueprints.auth.models import JWT, User
from extensions.db import db
from extensions.bcrypt import bcrypt
import uuid

auth_bl = Blueprint('auth_bl', __name__)

@auth_bl.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    rftk = data.get('rftk')
    frontend_cleanup = False

    user = User.query.filter_by(username=username).first()
    if not user:
        return {'message': 'user not found'}, 401
    elif not bcrypt.check_password_hash(user.password, password):
        return {'message': 'password is invalid'}

    # Refresh Token proccess at login

    if rftk:
        frontend_cleanup = True
        current_user_jwt_database = JWT.query.filter_by(user_name=username)
        current_rftk = current_user_jwt_database.filter(JWT.rftk==rftk).first()
        if current_rftk:
            if current_rftk.user_name == username:
                # clean up
                db.session.delete(current_rftk)
                db.session.commit()
            elif current_rftk.user_name != username:
                # Refresh token reuse detection
                hacked_user_jwt_database = JWT.query.filter_by(user_name=current_rftk.user_name).first()
                db.session.delete(hacked_user_jwt_database)
                db.session.commit()

                return {'message': 'refresh token is not found'}
        else:
            return {'message': 'refresh token is not found'}
    else:
        pass
    
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    new_rftk = JWT(rftk=refresh_token, user_id=user.id, user_name=user.username)
    
    
    db.session.add(new_rftk)
    db.session.commit()

    return {'actk': access_token, 'rftk': refresh_token, 'needs_cleanup': True if frontend_cleanup else False}

@auth_bl.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = uuid.uuid4()
    username = data.get('username')
    password = bcrypt.generate_password_hash(data.get('password'))
    email = data.get('email')
    job = data.get('job') if data.get('job') else 'not provided'

    if not username and password and email:
        return {'message': 'please fill all the fields'}

    new_user = User(id=str(user_id), username=username, password=password, avatar='none', email=email, job=job)
    db.session.add(new_user)
    db.session.commit()

    return {'message': 'success'}

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
            return {'message': 'refresh token is not found'}
        else:

            db.session.delete(hacked_user_jwt_database)
            db.session.commit()

            return {'message': 'refresh token is not found'}
    
    db.session.delete(current_rftk)
    db.session.commit()
    
    new_access_token = create_access_token(identity=current_user_name)
    new_refresh_token = create_refresh_token(identity=current_user_name)

    current_user = User.query.filter_by(username=current_user_name).first()

    db.session.add(JWT(rftk=new_refresh_token, user_id=current_user.id, user_name=current_user_name))
    db.session.commit()

    return {'rftk': new_refresh_token, 'actk': new_access_token}

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
        return {'message': 'user not found'}
    
    current_user_data = current_user.to_dict()
    
    return current_user_data

    





    
        