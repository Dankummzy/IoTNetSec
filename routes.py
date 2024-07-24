from flask import render_template, request, session, jsonify, redirect, flash, url_for
from flask_login import login_user, current_user, logout_user, login_required
from flask_app.models import User, Alert, Role, Permission, LoginAttempt, AccessLog, Device, User
from flask_app.crypto_utils import generate_keys, sign_data, verify_signature, serialize_key, deserialize_key
from flask_app.ids import start_sniffing
from flask_app import app, db, bcrypt
import threading
import traceback
from flask_mail import Message
from flask_app import mail
import random
from flask_app.forms import AddDeviceForm


@app.route('/')
def home():
    is_authenticated = current_user.is_authenticated
    return render_template('index.html', title='Home', is_authenticated=is_authenticated)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route('/generate_keys', methods=['POST'])
@login_required
def generate_user_keys():
    try:
        private_key, public_key = generate_keys()
        current_user.private_key = serialize_key(private_key, is_private=True)
        current_user.public_key = serialize_key(public_key)
        db.session.commit()
        app.logger.info(f'Keys generated for user {current_user.username}')
        return jsonify({'message': 'Keys generated successfully!'}), 201
    except Exception as e:
        app.logger.error('Failed to generate keys', exc_info=e)
        return jsonify({'message': 'Failed to generate keys'}), 500

@app.route('/sign_data', methods=['POST'])
@login_required
def sign_user_data():
    try:
        data = request.get_json()['data']
        private_key = deserialize_key(current_user.private_key, is_private=True)
        signature = sign_data(private_key, data)
        app.logger.info(f'Data signed for user {current_user.username}')
        return jsonify({'signature': signature.hex()}), 200
    except Exception as e:
        app.logger.error('Failed to sign data', exc_info=e)
        return jsonify({'message': 'Failed to sign data'}), 500

@app.route('/verify_signature', methods=['POST'])
def verify_user_signature():
    try:
        data = request.get_json()['data']
        signature = bytes.fromhex(request.get_json()['signature'])
        username = request.get_json()['username']
        user = User.query.filter_by(username=username).first()
        if not user:
            app.logger.warning(f'User {username} not found')
            return jsonify({'message': 'User not found'}), 404

        public_key = deserialize_key(user.public_key)
        is_valid = verify_signature(public_key, data, signature)
        app.logger.info(f'Signature verification for user {username} is {"valid" if is_valid else "invalid"}')
        return jsonify({'is_valid': is_valid}), 200
    except Exception as e:
        app.logger.error('Failed to verify signature', exc_info=e)
        return jsonify({'message': 'Failed to verify signature'}), 500

@app.before_first_request
def start_ids():
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.logger.info('Started packet sniffing thread')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        role = Role.query.filter_by(name=data['role']).first()
        if not role:
            app.logger.warning('Role does not exist')
            return jsonify({'message': 'Role does not exist'}), 400

        new_user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            role=role
        )
        
        # Generate keys for the new user
        private_key, public_key = generate_keys()
        new_user.private_key = serialize_key(private_key, is_private=True)
        new_user.public_key = serialize_key(public_key)

        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f'User {data["username"]} registered successfully with keys generated')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            if user.secret_key:
                # Generate OTP
                otp = generate_otp()
                
                # Send OTP via email
                send_otp_email(user.email, otp)
                
                # Store OTP in session for verification
                session['otp'] = otp
                session['username'] = user.username
                
                return redirect(url_for('verify_otp'))
            else:
                login_user(user)
                log_access_attempt(user.username, 'login', True)
                app.logger.info(f'User {user.username} logged in successfully')
                return redirect(url_for('alerts'))
        log_access_attempt(data['username'], 'login', False)
        app.logger.warning(f'Invalid credentials for user {data["username"]}')
        return jsonify({'message': 'Invalid credentials'}), 401
    # Handle GET request (return login form)
    return render_template('login.html', title='Login')

def generate_otp():
    # Generate a random 6-digit OTP
    otp = ''.join(random.choices('0123456789', k=6))
    return otp

def send_otp_email(email, otp):
    msg = Message('Login OTP', recipients=[email])
    msg.body = f'Your one-time password (OTP) for login is: {otp}'
    mail.send(msg)
    app.logger.info('OTP email sent successfully')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'username' not in session:
        flash('OTP or username not found in session', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_attempt = request.form.get('otp')
        if otp_attempt == session['otp']:
            # OTP verification successful, log in the user
            username = session['username']
            user = User.query.filter_by(username=username).first()
            login_user(user)
            log_access_attempt(user.username, 'login', True)
            app.logger.info(f'User {user.username} logged in successfully')

            # Clear OTP from session
            session.pop('otp', None)

            # Generate signature of the login event
            private_key = deserialize_key(user.private_key, is_private=True)
            signature = sign_data(private_key, f'{username} logged in at {datetime.utcnow()}')
            app.logger.info(f'Login event signed for user {username}')
            
            return jsonify({'message': 'Login successful', 'signature': signature.hex()})
        else:
            # Invalid OTP
            flash('Invalid OTP', 'danger')
            return redirect(url_for('login'))
    
    return render_template('verify_otp.html')

@app.route('/verify_login_signature', methods=['POST'])
def verify_login_signature():
    try:
        data = request.get_json()['data']
        signature = bytes.fromhex(request.get_json()['signature'])
        username = request.get_json()['username']
        user = User.query.filter_by(username=username).first()
        if not user:
            app.logger.warning(f'User {username} not found')
            return jsonify({'message': 'User not found'}), 404

        public_key = deserialize_key(user.public_key)
        is_valid = verify_signature(public_key, data, signature)
        app.logger.info(f'Login signature verification for user {username} is {"valid" if is_valid else "invalid"}')
        return jsonify({'is_valid': is_valid}), 200
    except Exception as e:
        app.logger.error('Failed to verify login signature', exc_info=e)
        return jsonify({'message': 'Failed to verify login signature'}), 500

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate and send password reset token
            token = user.get_reset_token()
            # Send email with reset link containing the token
            send_password_reset_email(user.email, token)
            flash('An email with instructions to reset your password has been sent to your email address.', 'success')
        else:
            flash('Email address not found. Please check and try again.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


def send_password_reset_email(email, token):
    msg = Message('Password Reset Request', sender='smarthome@gmail.com', recipients=[email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}

    If you did not make this request then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired token. Please try again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        user.set_password(new_password)
        db.session.commit()
        flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

def log_access_attempt(username, action, success):
    try:
        login_attempt = LoginAttempt(username=username, action=action, success=success)
        db.session.add(login_attempt)
        db.session.commit()
        app.logger.info(f'Logged access attempt for user {username}')
    except Exception as e:
        app.logger.error('Error logging access attempt', exc_info=e)
        db.session.rollback()

def send_lock_notification(user):
    subject = "Account Locked Notification"
    recipients = [user.email]
    body = f"Dear {user.username},\n\nYour account has been locked due to multiple failed login attempts. Please contact support for assistance.\n\nBest regards,\nYour Application Team"

    msg = Message(subject=subject, recipients=recipients, body=body)

    try:
        mail.send(msg)
        app.logger.info('Lock notification email sent successfully')
    except Exception as e:
        app.logger.error('Error sending lock notification email', exc_info=e)

@app.route('/unlock_account/<username>', methods=['GET'])
@login_required
def unlock_account(username):
    if current_user.role.name == 'Owner':
        return render_template('unlock_account.html', username=username)
    else:
        flash('Only administrators can unlock accounts', 'danger')
        return redirect(url_for('home'))

@app.route('/unlock_account/<username>/confirm', methods=['POST'])
def unlock_account_confirm(username):
    if current_user.is_authenticated and current_user.role.name == 'Owner':
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_locked = False
            db.session.commit()
            flash(f'Account for {username} unlocked successfully', 'success')
        else:
            flash('User not found', 'danger')
        return redirect(url_for('login'))
    else:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    username = current_user.username if current_user.is_authenticated else 'Unknown'
    logout_user()
    app.logger.info(f'User {username} logged out')
    return redirect(url_for('login'))

@app.route('/alerts', methods=['GET'])
@login_required
def alerts():
    if current_user.role.name != 'Owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))
    alerts = Alert.query.all()
    app.logger.info(f'Fetched alerts: {alerts}')  # Log fetched alerts
    return render_template('alerts.html', title='Alerts', alerts=alerts)


@app.route('/alerts_data', methods=['GET'])
@login_required
def alerts_data():
    if current_user.role.name != 'Owner':
        app.logger.warning(f'Unauthorized access attempt to alerts data by user {current_user.username}')
        return jsonify({'message': 'Unauthorized access'}), 403

    try:
        alerts = Alert.query.all()
        alerts_data = []
        for alert in alerts:
            alert_dict = {
                'alert': alert.alert_type,
                'data': {
                    'packet_length': alert.packet_length,
                    'src_ip': alert.src_ip,
                    'dst_ip': alert.dst_ip,
                    'protocol': alert.protocol,
                    'src_port': alert.src_port,
                    'dst_port': alert.dst_port,
                    'timestamp': alert.timestamp.isoformat(),  # Ensure timestamp is in ISO format
                    'duration': alert.duration,
                    'protocol_type': alert.protocol_type,
                    'service': alert.service,
                    'flag': alert.flag,
                    'src_bytes': alert.src_bytes,
                    'dst_bytes': alert.dst_bytes,
                    'land': alert.land,
                    'wrong_fragment': alert.wrong_fragment,
                    'urgent': alert.urgent,
                    'hot': alert.hot,
                    'num_failed_logins': alert.num_failed_logins,
                    'logged_in': alert.logged_in,
                    'num_compromised': alert.num_compromised,
                    'root_shell': alert.root_shell,
                    'su_attempted': alert.su_attempted,
                    'num_root': alert.num_root,
                    'num_file_creations': alert.num_file_creations,
                    'num_shells': alert.num_shells,
                    'num_access_files': alert.num_access_files,
                    'num_outbound_cmds': alert.num_outbound_cmds,
                    'is_host_login': alert.is_host_login,
                    'is_guest_login': alert.is_guest_login,
                    'count': alert.count,
                    'srv_count': alert.srv_count,
                    'serror_rate': alert.serror_rate,
                    'srv_serror_rate': alert.srv_serror_rate,
                    'rerror_rate': alert.rerror_rate,
                    'srv_rerror_rate': alert.srv_rerror_rate,
                    'same_srv_rate': alert.same_srv_rate,
                    'diff_srv_rate': alert.diff_srv_rate,
                    'srv_diff_host_rate': alert.srv_diff_host_rate,
                    'dst_host_count': alert.dst_host_count,
                    'dst_host_srv_count': alert.dst_host_srv_count,
                    'dst_host_same_srv_rate': alert.dst_host_same_srv_rate,
                    'dst_host_diff_srv_rate': alert.dst_host_diff_srv_rate,
                    'dst_host_same_src_port_rate': alert.dst_host_same_src_port_rate,
                    'dst_host_srv_diff_host_rate': alert.dst_host_srv_diff_host_rate,
                    'dst_host_serror_rate': alert.dst_host_serror_rate,
                    'dst_host_srv_serror_rate': alert.dst_host_srv_serror_rate,
                    'dst_host_rerror_rate': alert.dst_host_rerror_rate,
                    'dst_host_srv_rerror_rate': alert.dst_host_srv_rerror_rate
                }
            }
            alerts_data.append(alert_dict)
        return jsonify(alerts_data), 200
    except Exception as e:
        app.logger.error('Failed to fetch alerts', exc_info=e)
        return jsonify({'message': 'Failed to fetch alerts'}), 500

@app.route('/access_logs', methods=['GET'])
@login_required
def access_logs():
    if current_user.role.name == 'Owner':
        access_logs = AccessLog.query.all()
        app.logger.info(f'Fetched access logs: {access_logs}')  # Log fetched access logs
        return render_template('access_logs.html', access_logs=access_logs)
    else:
        app.logger.warning(f'Unauthorized access attempt to view access logs by user {current_user.username}')
        return jsonify({'message': 'Unauthorized access'}), 403


@app.route('/allocate_permissions', methods=['POST'])
@login_required
def allocate_permissions():
    if current_user.role.name == 'Owner':
        data = request.get_json()
        user_id = data.get('user_id')
        device = data.get('device')
        permission = data.get('permission')

        user = User.query.get(user_id)
        if not user:
            app.logger.warning(f'User {user_id} not found for permission allocation')
            return jsonify({'message': 'User not found'}), 404

        role = Role.query.filter_by(name=permission).first()
        if not role:
            app.logger.warning('Invalid role/permission')
            return jsonify({'message': 'Invalid role/permission'}), 400

        new_permission = Permission(device=device, role=role)
        db.session.add(new_permission)
        db.session.commit()
        app.logger.info(f'Permissions allocated successfully for user {user.username}')
        return jsonify({'message': 'Permissions allocated successfully'}), 200
    else:
        app.logger.warning(f'Unauthorized access attempt to allocate permissions by user {current_user.username}')
        return jsonify({'message': 'Unauthorized access'}), 403

@app.route('/anomalies')
@login_required
def anomalies():
    page = request.args.get('page', 1, type=int)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=10)
    app.logger.info(f'Fetched anomalies: {alerts.items}')  # Log fetched anomalies
    return render_template('anomalies.html', alerts=alerts)



@app.route('/anomaly-details/<int:alert_id>')
@login_required
def anomaly_details(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    app.logger.info(f'Fetched anomaly details for alert ID {alert_id}: {alert}')  # Log fetched anomaly details
    return render_template('anomaly_details.html', alert=alert)


@app.route('/devices', methods=['GET'])
@login_required
def devices():
    user_device_ids = []
    if current_user.role.name == 'Owner':
        devices = Device.query.all()
    else:
        devices = Device.query.join(Permission).filter(Permission.role_id == current_user.role_id).all()
        user_device_ids = [device.id for device in devices]
    return render_template('devices.html', devices=devices, user_device_ids=user_device_ids)


@app.route('/toggle_device/<int:device_id>', methods=['POST'])
@login_required
def toggle_device(device_id):
    device = Device.query.get_or_404(device_id)
    if current_user.role.name != 'Owner':
        permission = Permission.query.filter_by(role_id=current_user.role_id, device_id=device_id).first()
        if not permission and device.user_id != current_user.id:
            flash('Unauthorized action', 'danger')
            return redirect(url_for('devices'))

    device.status = not device.status
    db.session.commit()
    flash('Device status toggled', 'success')
    return redirect(url_for('devices'))

@app.route('/add_device', methods=['GET', 'POST'])
@login_required
def add_device():
    if current_user.role.name != 'Owner':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('devices'))

    form = AddDeviceForm()
    if form.validate_on_submit():
        device = Device(name=form.name.data, status=form.status.data, user_id=current_user.id)
        db.session.add(device)
        db.session.commit()
        flash('Device added successfully!', 'success')
        return redirect(url_for('devices'))
    
    return render_template('add_device.html', form=form)

@app.route('/device/<int:device_id>', methods=['GET', 'POST'])
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    if current_user.role.name != 'Owner' and device.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('devices'))

    if request.method == 'POST':
        device.name = request.form['device_name']
        db.session.commit()
        flash('Device updated successfully', 'success')
        return redirect(url_for('devices'))

    return render_template('device_detail.html', device=device)

@app.route('/device/delete/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    if current_user.role.name != 'Owner' and device.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('devices'))

    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully', 'success')
    return redirect(url_for('devices'))

@app.route('/assign_device', methods=['GET', 'POST'])
@login_required
def assign_device():
    if current_user.role.name != 'Owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('devices'))

    if request.method == 'POST':
        role_id = request.form['role_id']
        device_id = request.form['device_id']
        permission = Permission(role_id=role_id, device_id=device_id)
        db.session.add(permission)
        db.session.commit()
        flash('Device assigned to role successfully', 'success')
        return redirect(url_for('assign_device'))

    roles = Role.query.all()
    devices = Device.query.all()
    return render_template('assign_device.html', roles=roles, devices=devices)

@app.route('/remove_assignment', methods=['POST'])
@login_required
def remove_assignment():
    if current_user.role.name != 'Owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('devices'))

    role_id = request.form['role_id']
    device_id = request.form['device_id']
    permission = Permission.query.filter_by(role_id=role_id, device_id=device_id).first()
    if permission:
        db.session.delete(permission)
        db.session.commit()
        flash('Device assignment removed successfully', 'success')
    else:
        flash('No such assignment found', 'danger')

    return redirect(url_for('assign_device'))