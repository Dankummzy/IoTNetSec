import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_app import app, socketio

if __name__ == '__main__':
    socketio.run(app)