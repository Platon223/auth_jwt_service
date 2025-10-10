from flask import Flask, request, jsonify
from extensions.db import db
from extensions.jwt import jwt
from extensions.bcrypt import bcrypt
from extensions.mail import mail
from flask_migrate import Migrate
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv()

def create_service():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./auth.db'
    app.config['JWT_SECRET_KEY'] = '123SecretJWTKey'
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=50)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(minutes=2)
    app.config["MAIL_SERVER"] = 'smtp.sendgrid.net'
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USERNAME"] = 'apikey'
    app.config["MAIL_PASSWORD"] = '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'
    app.config["MAIL_DEFAULT_SENDER"] = 'platon.tikhnenko@gmail.com'

    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)


    @jwt.expired_token_loader
    def expired_access_token(jwt_header, jwt_payload):
        token = jwt_payload.get('type')
        return jsonify({'message': f'{token} token has expired'})
    
    @jwt.invalid_token_loader
    def invalid(callback):
        return jsonify({'message': 'Invalid access token'})
    
    @jwt.unauthorized_loader
    def unauth(callback):
        return jsonify({'message': 'no token provided'})

    # Register blueprints here
    from blueprints.auth.routes import auth_bl
    
    app.register_blueprint(auth_bl, url_prefix='/auth')

    from blueprints.auth.models import User, JWT

    migrate = Migrate(app, db)

    return app

