from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import Config

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
