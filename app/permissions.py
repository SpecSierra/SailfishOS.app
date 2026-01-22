"""
Role-based permission system for Sailfishos.app

Role Hierarchy:
    Admin (level 3) - All permissions
        └── Moderator (level 2) - Limited moderation permissions
              └── User (level 1) - Basic user permissions
"""
from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user


# Permission constants
CAN_ADD_APP = 'can_add_app'
CAN_EDIT_APP = 'can_edit_app'
CAN_DELETE_APP = 'can_delete_app'
CAN_ADD_REPORT = 'can_add_report'
CAN_DELETE_REPORT = 'can_delete_report'
CAN_MANAGE_USERS = 'can_manage_users'
CAN_MANAGE_CATEGORIES = 'can_manage_categories'
CAN_REFRESH_PLAYSTORE = 'can_refresh_playstore'
CAN_VIEW_LOGS = 'can_view_logs'
CAN_ROLLBACK = 'can_rollback'

# Role levels for hierarchy comparisons
ROLE_LEVELS = {
    'user': 1,
    'moderator': 2,
    'admin': 3
}

# Role to permission mapping
ROLE_PERMISSIONS = {
    'user': {
        CAN_ADD_APP,
        CAN_ADD_REPORT,
    },
    'moderator': {
        CAN_ADD_APP,
        CAN_ADD_REPORT,
        CAN_DELETE_REPORT,
        CAN_REFRESH_PLAYSTORE,
    },
    'admin': {
        CAN_ADD_APP,
        CAN_EDIT_APP,
        CAN_DELETE_APP,
        CAN_ADD_REPORT,
        CAN_DELETE_REPORT,
        CAN_MANAGE_USERS,
        CAN_MANAGE_CATEGORIES,
        CAN_REFRESH_PLAYSTORE,
        CAN_VIEW_LOGS,
        CAN_ROLLBACK,
    }
}


def get_role_level(role):
    """Get the numeric level for a role."""
    return ROLE_LEVELS.get(role, 0)


def get_permissions_for_role(role):
    """Get all permissions for a given role."""
    return ROLE_PERMISSIONS.get(role, set())


def check_permission(user, permission):
    """
    Check if a user has a specific permission.

    Args:
        user: The user object (must have a 'role' attribute)
        permission: The permission constant to check

    Returns:
        bool: True if user has the permission, False otherwise
    """
    if not user or not hasattr(user, 'role'):
        return False

    user_permissions = get_permissions_for_role(user.role)
    return permission in user_permissions


def has_permission(permission):
    """
    Decorator to require a specific permission for a view.

    Usage:
        @has_permission(CAN_DELETE_APP)
        def delete_app(app_id):
            ...

    Args:
        permission: The permission constant to require

    Returns:
        The decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('dashboard.login'))

            if not check_permission(current_user, permission):
                flash('You do not have permission to perform this action.', 'danger')
                return redirect(url_for('dashboard.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def has_any_permission(*permissions):
    """
    Decorator to require any of the specified permissions.

    Usage:
        @has_any_permission(CAN_EDIT_APP, CAN_DELETE_APP)
        def manage_app(app_id):
            ...

    Args:
        *permissions: Permission constants (user needs at least one)

    Returns:
        The decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('dashboard.login'))

            for permission in permissions:
                if check_permission(current_user, permission):
                    return f(*args, **kwargs)

            flash('You do not have permission to perform this action.', 'danger')
            return redirect(url_for('dashboard.index'))
        return decorated_function
    return decorator


def has_all_permissions(*permissions):
    """
    Decorator to require all specified permissions.

    Usage:
        @has_all_permissions(CAN_MANAGE_USERS, CAN_VIEW_LOGS)
        def admin_panel():
            ...

    Args:
        *permissions: Permission constants (user needs all of them)

    Returns:
        The decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('dashboard.login'))

            for permission in permissions:
                if not check_permission(current_user, permission):
                    flash('You do not have permission to perform this action.', 'danger')
                    return redirect(url_for('dashboard.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def can_manage_user(actor, target_user):
    """
    Check if an actor can manage (edit/ban) a target user.

    Args:
        actor: The user performing the action
        target_user: The user being managed

    Returns:
        bool: True if actor can manage target_user
    """
    if not actor or not target_user:
        return False

    # Can't manage yourself
    if actor.id == target_user.id:
        return False

    # Must have user management permission
    if not check_permission(actor, CAN_MANAGE_USERS):
        return False

    # Can only manage users of lower or equal level (but not same level for admins)
    actor_level = get_role_level(actor.role)
    target_level = get_role_level(target_user.role)

    # Admins can manage moderators and users, but not other admins
    if actor.role == 'admin' and target_user.role == 'admin':
        return False

    return actor_level > target_level


def get_role_badge_class(role):
    """Get Bootstrap badge class for a role."""
    badge_classes = {
        'admin': 'badge-danger',
        'moderator': 'badge-warning',
        'user': 'badge-info'
    }
    return badge_classes.get(role, 'badge-secondary')


def get_role_display_name(role):
    """Get human-readable display name for a role."""
    display_names = {
        'admin': 'Administrator',
        'moderator': 'Moderator',
        'user': 'User'
    }
    return display_names.get(role, role.title())


# Export permission constants for easy importing
__all__ = [
    # Permission constants
    'CAN_ADD_APP',
    'CAN_EDIT_APP',
    'CAN_DELETE_APP',
    'CAN_ADD_REPORT',
    'CAN_DELETE_REPORT',
    'CAN_MANAGE_USERS',
    'CAN_MANAGE_CATEGORIES',
    'CAN_REFRESH_PLAYSTORE',
    'CAN_VIEW_LOGS',
    'CAN_ROLLBACK',
    # Functions
    'check_permission',
    'has_permission',
    'has_any_permission',
    'has_all_permissions',
    'get_permissions_for_role',
    'get_role_level',
    'can_manage_user',
    'get_role_badge_class',
    'get_role_display_name',
    'ROLE_PERMISSIONS',
    'ROLE_LEVELS',
]
