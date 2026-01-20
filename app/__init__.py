import logging
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

login_manager = LoginManager()
login_manager.login_view = 'dashboard.login'
login_manager.login_message_category = 'info'

csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    login_manager.init_app(app)
    csrf.init_app(app)

    from app.routes.frontend import frontend_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(frontend_bp)
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    @app.context_processor
    def inject_app_version():
        return {'app_version': app.config.get('APP_VERSION', 'dev')}

    return app
