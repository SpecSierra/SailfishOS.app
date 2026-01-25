from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from config import Config

login_manager = LoginManager()
login_manager.login_view = 'dashboard.login'
login_manager.login_message_category = 'info'

csrf = CSRFProtect()

# Rate limiter for preventing brute force attacks
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Secure session cookie settings
    app.config.update(
        SESSION_COOKIE_SECURE=not config_class.DEV_MODE,  # HTTPS only in production
        SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access
        SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    )

    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Configure CORS - restrict to same origin by default
    # Only allow cross-origin requests from the same domain
    CORS(app, resources={
        r"/icons/*": {"origins": "*"},  # Icons can be loaded from anywhere
    }, supports_credentials=False)

    from app.routes.frontend import frontend_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(frontend_bp)
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    @app.context_processor
    def inject_app_version():
        return {'app_version': app.config.get('APP_VERSION', 'dev')}

    @app.template_filter('get_entity_icon')
    def get_entity_icon(entity_type):
        """Get FontAwesome icon class for entity type."""
        icons = {
            'app': 'fa-mobile-alt',
            'report': 'fa-clipboard-list',
            'user': 'fa-user',
            'category': 'fa-tags',
        }
        return icons.get(entity_type, 'fa-question')

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses to prevent common attacks."""
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Enable XSS filter in browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Content Security Policy (adjust as needed for your assets)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://newassets.hcaptcha.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: https: blob:; "
            "frame-src https://newassets.hcaptcha.com https://hcaptcha.com; "
            "connect-src 'self' https://hcaptcha.com"
        )
        # Permissions Policy (formerly Feature-Policy)
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        # HTTP Strict Transport Security (HSTS) - only in production
        if not app.config.get('DEV_MODE', False):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.context_processor
    def inject_permissions():
        """Inject permission checking functions into templates."""
        from app.permissions import (
            check_permission, get_role_badge_class, get_role_display_name,
            CAN_ADD_APP, CAN_EDIT_APP, CAN_DELETE_APP,
            CAN_ADD_REPORT, CAN_DELETE_REPORT,
            CAN_MANAGE_USERS, CAN_MANAGE_CATEGORIES,
            CAN_REFRESH_PLAYSTORE, CAN_VIEW_LOGS, CAN_ROLLBACK
        )
        from flask_login import current_user

        def has_permission(permission):
            """Check if current user has a permission."""
            if not current_user.is_authenticated:
                return False
            return check_permission(current_user, permission)

        return {
            'has_permission': has_permission,
            'get_role_badge_class': get_role_badge_class,
            'get_role_display_name': get_role_display_name,
            # Permission constants for templates
            'CAN_ADD_APP': CAN_ADD_APP,
            'CAN_EDIT_APP': CAN_EDIT_APP,
            'CAN_DELETE_APP': CAN_DELETE_APP,
            'CAN_ADD_REPORT': CAN_ADD_REPORT,
            'CAN_DELETE_REPORT': CAN_DELETE_REPORT,
            'CAN_MANAGE_USERS': CAN_MANAGE_USERS,
            'CAN_MANAGE_CATEGORIES': CAN_MANAGE_CATEGORIES,
            'CAN_REFRESH_PLAYSTORE': CAN_REFRESH_PLAYSTORE,
            'CAN_VIEW_LOGS': CAN_VIEW_LOGS,
            'CAN_ROLLBACK': CAN_ROLLBACK,
        }

    return app
