import logging
from logging.handlers import RotatingFileHandler
import os

LOG_FILE = 'app.log'

if not os.path.exists('logs'):
    os.makedirs('logs')

log_handler = RotatingFileHandler(os.path.join('logs', LOG_FILE), maxBytes=100000, backupCount=10)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
log_handler.setFormatter(log_formatter)

def setup_logging(app):
    if not app.debug:
        app.logger.addHandler(log_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Logging setup complete')

