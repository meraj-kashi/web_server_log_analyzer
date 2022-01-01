from flask_wtf import FlaskForm
from wtforms import StringField, DateTimeField, SubmitField, FileField
from wtforms.validators import IPAddress


class SearchForm(FlaskForm):
    content = FileField('log_file', validators=[])
    config = FileField('config_file', validators=[])
    start_time = DateTimeField('start_time', validators=[])
    end_time = DateTimeField('end_time', validators=[])
    status_code = StringField('status_code', validators=[])
    source_ip = StringField('source_ip', validators=[IPAddress()])
    os = StringField('os', validators=[])
    browser = StringField('browser', validators=[])
    user_regex_syntax = StringField('user_regex_syntax', validators=[])

    submit = SubmitField('Search Log')
