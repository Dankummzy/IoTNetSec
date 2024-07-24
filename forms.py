from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class AddDeviceForm(FlaskForm):
    name = StringField('Device Name', validators=[DataRequired()])
    status = BooleanField('Status')  # Checkbox for initial status
    submit = SubmitField('Add Device')