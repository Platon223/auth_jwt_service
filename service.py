from flask import Flask, request, jsonify, Response
from extensions.db import db
from extensions.jwt import jwt
from extensions.bcrypt import bcrypt
from extensions.mail import mail
from extensions.oauth import oauth
from flask_migrate import Migrate
from datetime import timedelta
from dotenv import load_dotenv
import os
from prometheus_client import Counter, Summary, generate_latest, CONTENT_TYPE_LATEST
from logg.log import setup
import logging

load_dotenv()

def create_service():
    app = Flask(__name__)
    setup()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    REQUEST_COUNT = Counter("service_requests_total", "Total number of auth's service requests", ["method", "endpoint"])
    EXCEPTIONS = Counter("service_exceptions_total", "Total number when service crashed", ["endpoint", "exception_type"])
    app.secret_key = os.getenv('APP_SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./auth.db'
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=2)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(minutes=5)
    app.config["MAIL_SERVER"] = 'smtp.sendgrid.net'
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USE_SSL"] = False
    app.config["MAIL_USERNAME"] = 'apikey'
    app.config["MAIL_PASSWORD"] = os.getenv('SENDGRID_API_KEY')
    app.config["MAIL_DEFAULT_SENDER"] = 'platon.tikhnenko@gmail.com'

    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    oauth.init_app(app)
    
    @app.errorhandler(Exception)
    def catch_all(e):
        EXCEPTIONS.labels(endpoint=request.path, exception_type=type(e).__name__).inc()
        return {"message": f"error: {e}"}

    @app.before_request
    def counter():
        if request.path == "/metrics": return
        REQUEST_COUNT.labels(method=request.method, endpoint=request.path).inc()

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
    

    @app.route("/metrics", methods=["GET"])
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    # Register blueprints here
    from blueprints.auth.routes import auth_bl
    
    app.register_blueprint(auth_bl, url_prefix='/auth')

    from blueprints.auth.models import User, JWT

    migrate = Migrate(app, db)

    return app

