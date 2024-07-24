import sys
import os

# Add the project directory to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_app import app, db  # Assuming you have a factory function to create your app
from flask_app.models import Role

def populate_roles():
    roles = ['Owner', 'Family Member', 'Guest', 'Service Provider']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():  # Check if role already exists
            role = Role(name=role_name)
            db.session.add(role)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        populate_roles()