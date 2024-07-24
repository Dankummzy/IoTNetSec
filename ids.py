import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from scapy.all import sniff, IP, TCP
from flask_app.models import Alert
from flask_app import db, mail
from flask_mail import Message
from flask import current_app
from flask_app import app

# Load the trained Decision Tree Classifier model
model = joblib.load('DTC_Classifier_model.pkl')

# Initialize label encoders for categorical features
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()

# Fit encoders on training data (this should ideally be done during model training)
service_encoder.fit(['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u', 'ecr_i', 'other'])  # example services
flag_encoder.fit(['SF', 'S0', 'REJ', 'RSTR', 'RSTO', 'SH', 'S1'])  # example flags

def preprocess_packet(packet):
    """Extract features from packet for anomaly detection."""
    features = {
        'duration': len(packet),
        'protocol_type': packet[IP].proto if packet.haslayer(IP) else None,
        'service': 'other',
        'flag': 'SF',
        'src_bytes': len(packet[TCP].payload) if packet.haslayer(TCP) else 0,
        'dst_bytes': len(packet[TCP].payload) if packet.haslayer(TCP) else 0,
        'land': 1 if packet.haslayer(IP) and packet[IP].src == packet[IP].dst else 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 0,
        'srv_count': 0,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 0.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 0,
        'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }
    app.logger.info(f"Packet preprocessed: {features}")
    return features

def detect_anomalies(features):
    """Detect anomalies in the given features."""
    features_df = pd.DataFrame([features])
    features_df = features_df.reindex(columns=model.feature_names_in_, fill_value=0)

    # Encode categorical features
    features_df['service'] = service_encoder.transform(features_df['service'])
    features_df['flag'] = flag_encoder.transform(features_df['flag'])

    prediction = model.predict(features_df)
    anomaly_detected = prediction[0] == 'anomaly'
    app.logger.info(f"Anomaly detected: {anomaly_detected}, Features: {features}")
    return anomaly_detected

def capture_packets(packet):
    """Capture and process packets for anomaly detection."""
    if packet.haslayer(IP):  # Only process packets with IP layer
        features = preprocess_packet(packet)
        if detect_anomalies(features):
            alert(features)

def alert(features):
    """Trigger an alert for detected anomalies."""
    try:
        with app.app_context():
            alert_data = Alert(
                alert_type='Intrusion detected',
                packet_length=features['duration'],
                src_ip=features.get('src_ip'),
                dst_ip=features.get('dst_ip'),
                protocol=features['protocol_type'],
                src_port=features.get('src_port'),
                dst_port=features.get('dst_port'),
                duration=features['duration'],
                protocol_type=features['protocol_type'],
                service=features['service'],
                flag=features['flag'],
                src_bytes=features['src_bytes'],
                dst_bytes=features['dst_bytes'],
                land=features['land'],
                wrong_fragment=features['wrong_fragment'],
                urgent=features['urgent'],
                hot=features['hot'],
                num_failed_logins=features['num_failed_logins'],
                logged_in=features['logged_in'],
                num_compromised=features['num_compromised'],
                root_shell=features['root_shell'],
                su_attempted=features['su_attempted'],
                num_root=features['num_root'],
                num_file_creations=features['num_file_creations'],
                num_shells=features['num_shells'],
                num_access_files=features['num_access_files'],
                num_outbound_cmds=features['num_outbound_cmds'],
                is_host_login=features['is_host_login'],
                is_guest_login=features['is_guest_login'],
                count=features['count'],
                srv_count=features['srv_count'],
                serror_rate=features['serror_rate'],
                srv_serror_rate=features['srv_serror_rate'],
                rerror_rate=features['rerror_rate'],
                srv_rerror_rate=features['srv_rerror_rate'],
                same_srv_rate=features['same_srv_rate'],
                diff_srv_rate=features['diff_srv_rate'],
                srv_diff_host_rate=features['srv_diff_host_rate'],
                dst_host_count=features['dst_host_count'],
                dst_host_srv_count=features['dst_host_srv_count'],
                dst_host_same_srv_rate=features['dst_host_same_srv_rate'],
                dst_host_diff_srv_rate=features['dst_host_diff_srv_rate'],
                dst_host_same_src_port_rate=features['dst_host_same_src_port_rate'],
                dst_host_srv_diff_host_rate=features['dst_host_srv_diff_host_rate'],
                dst_host_serror_rate=features['dst_host_serror_rate'],
                dst_host_srv_serror_rate=features['dst_host_srv_serror_rate'],
                dst_host_rerror_rate=features['dst_host_rerror_rate'],
                dst_host_srv_rerror_rate=features['dst_host_srv_rerror_rate']
            )
            db.session.add(alert_data)
            db.session.commit()

            send_email_alert(features)
            app.logger.info(f"Alert triggered and stored: {features}")
    except Exception as e:
        app.logger.error("Failed to trigger alert", exc_info=e)

def send_email_alert(features):
    subject = "Intrusion Detected"
    recipients = [current_app.config['ALERT_EMAIL']]
    body = "Alert Details:\n\n" + "\n".join(f"{key}: {value}" for key, value in features.items())

    msg = Message(subject=subject, recipients=recipients, body=body)
    try:
        mail.send(msg)
        app.logger.info("Email alert sent successfully")
    except Exception as e:
        app.logger.error("Failed to send email alert", exc_info=e)

def start_sniffing():
    """Start sniffing network traffic."""
    try:
        sniff(prn=capture_packets, store=False)
        app.logger.info("Started sniffing network traffic")
    except Exception as e:
        app.logger.error("Failed to start sniffing", exc_info=e)

if __name__ == "__main__":
    with app.app_context():
        start_sniffing()
