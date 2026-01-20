from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user


def role_required(*roles):
    """
    Decorator to require specific roles for a view.
    Usage: @role_required('admin') or @role_required('admin', 'moderator')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('dashboard.login'))

            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('frontend.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Shortcut decorator for admin-only views."""
    return role_required('admin')(f)


def moderator_required(f):
    """Shortcut decorator for moderator or admin views."""
    return role_required('admin', 'moderator')(f)


def check_not_banned(f):
    """Decorator to check if user is banned."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and getattr(current_user, 'is_banned', False):
            flash('Your account has been suspended.', 'danger')
            return redirect(url_for('frontend.index'))
        return f(*args, **kwargs)
    return decorated_function
