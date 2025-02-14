from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Updated ProxyFix configuration
app.wsgi_app = ProxyFix(
    app.wsgi_app, 
    x_for=1,      # Number of proxy servers
    x_proto=1,    # Number of proxies that set X-Forwarded-Proto
    x_host=1      # Number of proxies that set X-Forwarded-Host
)

from app import routes, models