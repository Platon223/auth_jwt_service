from extensions.db import db
from sqlalchemy import Column, Text, Integer, DateTime
from extensions.bcrypt import bcrypt

class User(db.Model):
    __tablename__ = 'Users'

    id = Column(Text, primary_key=True)
    username = Column(Text, nullable=False)
    password = Column(Text, nullable=False)
    avatar = Column(Text, nullable=False)
    email = Column(Text, nullable=False)
    job = Column(Text, nullable=True)

    def check_password(self, password):
        return bcrypt.check_password_hash(password, self.password)
    def set_password(self, password):
        self.password = password
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'avatar': self.avatar,
            'email': self.email,
            'job': self.job
        }


class JWT(db.Model):
    __tablename__ = 'JWT'


    rftk = Column(Text, primary_key=True)
    user_id = Column(Text, nullable=False)
    user_name = Column(Text, nullable=False)


class AuthEntry(db.Model):
    __tablename__ = 'Codes'

    id = Column(Text, primary_key=True)
    code = Column(Text, nullable=False)
    user_id = Column(Text, nullable=False)
    expires_date = Column(DateTime, nullable=False)
