import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Flask-Mail configurations
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'danterkum16@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'hhbpaaoqmpqkcktx'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'danterkum16@gmail.com'
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL') or 'dtkpost01@gmail.com'

