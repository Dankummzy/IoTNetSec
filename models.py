from flask_login import UserMixin
from datetime import datetime
from flask_app.extensions import db, login_manager
# from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_app import bcrypt
from flask import current_app


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    private_key = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)
    secret_key = db.Column(db.String(16), nullable=True)
    password_reset_token = db.Column(db.String(100), nullable=True)
    devices = db.relationship('Device', back_populates='user')

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)
    permissions = db.relationship('Permission', back_populates='role')


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)

    role = db.relationship('Role', back_populates='permissions')
    device = db.relationship('Device', back_populates='permissions')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(100), nullable=False)
    packet_length = db.Column(db.Integer, nullable=False)
    src_ip = db.Column(db.String(100), nullable=False)
    dst_ip = db.Column(db.String(100), nullable=False)
    protocol = db.Column(db.Integer, nullable=False)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    duration = db.Column(db.Integer, nullable=False)
    protocol_type = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(100), nullable=True)
    flag = db.Column(db.String(10), nullable=True)
    src_bytes = db.Column(db.Integer, nullable=False)
    dst_bytes = db.Column(db.Integer, nullable=False)
    land = db.Column(db.Integer, nullable=False)
    wrong_fragment = db.Column(db.Integer, nullable=False)
    urgent = db.Column(db.Integer, nullable=False)
    hot = db.Column(db.Integer, nullable=False)
    num_failed_logins = db.Column(db.Integer, nullable=False)
    logged_in = db.Column(db.Integer, nullable=False)
    num_compromised = db.Column(db.Integer, nullable=False)
    root_shell = db.Column(db.Integer, nullable=False)
    su_attempted = db.Column(db.Integer, nullable=False)
    num_root = db.Column(db.Integer, nullable=False)
    num_file_creations = db.Column(db.Integer, nullable=False)
    num_shells = db.Column(db.Integer, nullable=False)
    num_access_files = db.Column(db.Integer, nullable=False)
    num_outbound_cmds = db.Column(db.Integer, nullable=False)
    is_host_login = db.Column(db.Integer, nullable=False)
    is_guest_login = db.Column(db.Integer, nullable=False)
    count = db.Column(db.Integer, nullable=False)
    srv_count = db.Column(db.Integer, nullable=False)
    serror_rate = db.Column(db.Float, nullable=False)
    srv_serror_rate = db.Column(db.Float, nullable=False)
    rerror_rate = db.Column(db.Float, nullable=False)
    srv_rerror_rate = db.Column(db.Float, nullable=False)
    same_srv_rate = db.Column(db.Float, nullable=False)
    diff_srv_rate = db.Column(db.Float, nullable=False)
    srv_diff_host_rate = db.Column(db.Float, nullable=False)
    dst_host_count = db.Column(db.Integer, nullable=False)
    dst_host_srv_count = db.Column(db.Integer, nullable=False)
    dst_host_same_srv_rate = db.Column(db.Float, nullable=False)
    dst_host_diff_srv_rate = db.Column(db.Float, nullable=False)
    dst_host_same_src_port_rate = db.Column(db.Float, nullable=False)
    dst_host_srv_diff_host_rate = db.Column(db.Float, nullable=False)
    dst_host_serror_rate = db.Column(db.Float, nullable=False)
    dst_host_srv_serror_rate = db.Column(db.Float, nullable=False)
    dst_host_rerror_rate = db.Column(db.Float, nullable=False)
    dst_host_srv_rerror_rate = db.Column(db.Float, nullable=False)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # 'login' or 'logout'
    success = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"LoginAttempt('{self.username}', '{self.action}', '{self.success}')"


class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    device = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"AccessLog(username={self.username}, device={self.device}, timestamp={self.timestamp}, success={self.success})"


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Boolean, default=False)  # False = Off, True = On
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', back_populates='devices')
    permissions = db.relationship('Permission', back_populates='device', lazy=True)
