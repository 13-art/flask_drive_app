from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, '..', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db_path = os.path.join(basedir, '..', 'instance', 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
from app.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from app import routes, models