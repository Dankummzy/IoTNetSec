#__init__.py:

from flask import Flask
from flask_app.config import Config
from flask_app.extensions import db, bcrypt, login_manager, migrate, mail
from flask_socketio import SocketIO
from flask_app.logging_config import setup_logging

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)
socketio = SocketIO(app)

setup_logging(app)

from . import routes, models