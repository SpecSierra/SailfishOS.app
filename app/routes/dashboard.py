import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, session, Response
from flask_login import login_user, logout_user, login_required, current_user
from app import login_manager, limiter
from app.models import DataManager, User
from app.forms import (
    LoginForm, AppForm, CategoryForm, RegistrationForm, ReportForm,
    TwoFactorSetupForm, TwoFactorVerifyForm, TwoFactorDisableForm,
    PasswordChangeForm, SUPPORTED_DEVICES, SFOS_VERSIONS
)
from app.utils import (
    fetch_play_store_icon, fetch_and_save_icon, fetch_and_update_app_info,
    verify_hcaptcha, is_totp_available, generate_totp_secret,
    generate_totp_qr_code, verify_totp, get_totp_uri
)
from app.decorators import role_required, admin_required, moderator_required, check_not_banned
from app.logs import LogManager
from app.permissions import (
    has_permission, check_permission,
    CAN_ADD_APP, CAN_EDIT_APP, CAN_DELETE_APP,
    CAN_ADD_REPORT, CAN_DELETE_REPORT,
    CAN_MANAGE_USERS, CAN_MANAGE_CATEGORIES,
    CAN_REFRESH_PLAYSTORE, CAN_VIEW_LOGS, CAN_ROLLBACK
)

# Account lockout configuration
MAX_FAILED_ATTEMPTS = 5  # Lock account after 5 failed attempts
LOCKOUT_DURATION_MINUTES = 15  # Lock for 15 minutes

# In-memory storage for failed login attempts (per username)
# Format: {username: {'count': int, 'first_attempt': datetime, 'locked_until': datetime or None}}
_failed_login_attempts = {}


def is_safe_url(target):
    """Check if the target URL is safe for redirection (prevents open redirect)."""
    if not target:
        return False
    # Parse the target URL
    parsed = urlparse(target)
    # Only allow relative URLs (no scheme or netloc)
    # This prevents redirects to external sites
    return not parsed.scheme and not parsed.netloc


def is_account_locked(username):
    """Check if an account is currently locked due to failed login attempts."""
    if username not in _failed_login_attempts:
        return False

    attempt_info = _failed_login_attempts[username]
    locked_until = attempt_info.get('locked_until')

    if locked_until:
        if datetime.utcnow() < locked_until:
            return True
        else:
            # Lockout expired, reset the counter
            del _failed_login_attempts[username]
            return False

    return False


def get_lockout_remaining_minutes(username):
    """Get the remaining lockout time in minutes."""
    if username not in _failed_login_attempts:
        return 0

    attempt_info = _failed_login_attempts[username]
    locked_until = attempt_info.get('locked_until')

    if locked_until and datetime.utcnow() < locked_until:
        remaining = locked_until - datetime.utcnow()
        return max(1, int(remaining.total_seconds() / 60))

    return 0


def record_failed_login(username):
    """Record a failed login attempt and lock account if threshold reached."""
    now = datetime.utcnow()

    if username not in _failed_login_attempts:
        _failed_login_attempts[username] = {
            'count': 1,
            'first_attempt': now,
            'locked_until': None
        }
    else:
        attempt_info = _failed_login_attempts[username]

        # Reset if the first attempt was more than lockout duration ago
        if now - attempt_info['first_attempt'] > timedelta(minutes=LOCKOUT_DURATION_MINUTES):
            _failed_login_attempts[username] = {
                'count': 1,
                'first_attempt': now,
                'locked_until': None
            }
        else:
            attempt_info['count'] += 1

            # Lock account if threshold reached
            if attempt_info['count'] >= MAX_FAILED_ATTEMPTS:
                attempt_info['locked_until'] = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                LogManager.log_security_event(
                    LogManager.SECURITY_ACCOUNT_LOCKED,
                    username=username,
                    description=f'Account locked after {MAX_FAILED_ATTEMPTS} failed login attempts'
                )
                return True  # Account is now locked

    return False  # Account not locked


def clear_failed_attempts(username):
    """Clear failed login attempts after successful login."""
    if username in _failed_login_attempts:
        del _failed_login_attempts[username]

dashboard_bp = Blueprint('dashboard', __name__)


@login_manager.user_loader
def load_user(user_id):
    return DataManager.get_user_by_id(user_id)


@dashboard_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit: 10 login attempts per minute per IP
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data

        # Check if account is locked due to failed attempts
        if is_account_locked(username):
            remaining = get_lockout_remaining_minutes(username)
            flash(f'Account temporarily locked due to too many failed attempts. Try again in {remaining} minutes.', 'danger')
            return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            LogManager.log_security_event(
                LogManager.SECURITY_CAPTCHA_FAILED,
                username=username,
                description='Failed captcha verification on login'
            )
            flash('Please complete the captcha verification.', 'danger')
            return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        user = DataManager.get_user_by_username(username)
        if user and user.check_password(form.password.data):
            if user.is_banned:
                LogManager.log_security_event(
                    LogManager.SECURITY_LOGIN_FAILED,
                    username=username,
                    description='Login attempt on banned account'
                )
                flash('Your account has been suspended.', 'danger')
                return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

            # Clear failed attempts on successful authentication
            clear_failed_attempts(username)

            # Check if 2FA is enabled
            if user.totp_enabled and user.totp_secret:
                # Store pending login in session for 2FA verification
                session['pending_2fa_user_id'] = user.id
                session['pending_2fa_remember'] = form.remember_me.data
                session['pending_2fa_next'] = request.args.get('next')
                return redirect(url_for('dashboard.verify_2fa'))

            # No 2FA - log in directly
            login_user(user, remember=form.remember_me.data)
            LogManager.log_security_event(
                LogManager.SECURITY_LOGIN_SUCCESS,
                username=user.username,
                description='Successful login'
            )
            next_page = request.args.get('next')
            flash('Logged in successfully.', 'success')
            # Validate next_page to prevent open redirect vulnerability (CWE-601)
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))

        # Record failed attempt and check if account should be locked
        account_locked = record_failed_login(username)
        LogManager.log_security_event(
            LogManager.SECURITY_LOGIN_FAILED,
            username=username,
            description='Invalid username or password'
        )
        if account_locked:
            flash(f'Account temporarily locked due to too many failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@dashboard_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA code during login."""
    # Check if there's a pending 2FA login
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        flash('No pending login found. Please log in again.', 'warning')
        return redirect(url_for('dashboard.login'))

    user = DataManager.get_user_by_id(user_id)
    if not user:
        session.pop('pending_2fa_user_id', None)
        session.pop('pending_2fa_remember', None)
        session.pop('pending_2fa_next', None)
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('dashboard.login'))

    form = TwoFactorVerifyForm()
    if form.validate_on_submit():
        if verify_totp(user.totp_secret, form.totp_code.data):
            # 2FA verified - complete login
            remember = session.pop('pending_2fa_remember', False)
            next_page = session.pop('pending_2fa_next', None)
            session.pop('pending_2fa_user_id', None)

            login_user(user, remember=remember)
            LogManager.log_security_event(
                LogManager.SECURITY_LOGIN_SUCCESS,
                username=user.username,
                description='Successful login with 2FA'
            )
            flash('Logged in successfully.', 'success')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))
        else:
            LogManager.log_security_event(
                LogManager.SECURITY_LOGIN_FAILED,
                username=user.username,
                description='Invalid 2FA code'
            )
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('dashboard/verify_2fa.html', form=form, username=user.username)


@dashboard_bp.route('/cancel-2fa')
def cancel_2fa():
    """Cancel pending 2FA login."""
    session.pop('pending_2fa_user_id', None)
    session.pop('pending_2fa_remember', None)
    session.pop('pending_2fa_next', None)
    flash('Login cancelled.', 'info')
    return redirect(url_for('dashboard.login'))


@dashboard_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit: 5 registrations per hour per IP
def register():
    if current_user.is_authenticated:
        return redirect(url_for('frontend.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            flash('Please complete the captcha verification.', 'danger')
            return render_template('dashboard/register.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Check if username already exists
        if DataManager.get_user_by_username(form.username.data):
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('dashboard/register.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Create the user
        user = DataManager.create_user(
            username=form.username.data,
            email='',
            password=form.password.data,
            role='user'
        )

        # Log the action (user self-registration)
        LogManager.log_action(
            user_id=user.id,
            username=user.username,
            action=LogManager.ACTION_USER_CREATED,
            entity_type='user',
            entity_id=user.id,
            old_data=None,
            new_data={'username': user.username, 'role': user.role},
            description=f'User self-registered: {user.username}'
        )

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('dashboard.login'))

    return render_template('dashboard/register.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@dashboard_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('frontend.index'))


@dashboard_bp.route('/')
@login_required
@check_not_banned
def index():
    # Regular users are redirected to their profile
    if current_user.role == 'user':
        return redirect(url_for('dashboard.profile'))

    apps = DataManager.get_apps()
    categories = DataManager.get_categories()
    reports = DataManager.get_reports()
    users = DataManager.get_users() if current_user.role == 'admin' else []
    return render_template(
        'dashboard/index.html',
        apps_count=len(apps),
        categories_count=len(categories),
        reports_count=len(reports),
        users_count=len(users)
    )


@dashboard_bp.route('/profile')
@login_required
@check_not_banned
def profile():
    """User profile page showing their contributions."""
    user_reports = DataManager.get_reports_for_user(current_user.id)
    apps = DataManager.get_apps()
    app_map = {app['id']: app for app in apps}
    user_reports = sorted(user_reports, key=lambda r: r.get('created_at', ''), reverse=True)
    return render_template(
        'dashboard/profile.html',
        reports=user_reports,
        app_map=app_map
    )


@dashboard_bp.route('/profile/delete', methods=['POST'])
@login_required
@check_not_banned
def profile_delete():
    """Delete user account and all associated data (GDPR compliance)."""
    user_id = current_user.id
    username = current_user.username

    # Log the deletion before we lose access to user info
    LogManager.log_action(
        user_id=user_id,
        username=username,
        action='account_deleted',
        entity_type='user',
        entity_id=user_id,
        old_data={'username': username},
        new_data=None,
        description=f'User self-deleted account: {username}'
    )

    # Logout first
    logout_user()

    # Delete all user's reports (GDPR cascade deletion)
    deleted_reports = DataManager.delete_reports_by_user(user_id)

    # Delete the user
    DataManager.delete_user(user_id)

    flash(f'Account "{username}" and {deleted_reports} associated report(s) have been deleted.', 'info')
    return redirect(url_for('frontend.index'))


@dashboard_bp.route('/profile/export-data')
@login_required
@check_not_banned
def profile_export_data():
    """Export all user data for GDPR compliance."""
    export_data = DataManager.export_user_data(current_user.id)

    if not export_data:
        flash('Could not export your data. Please try again.', 'danger')
        return redirect(url_for('dashboard.profile'))

    # Log the export action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='data_export',
        entity_type='user',
        entity_id=current_user.id,
        old_data=None,
        new_data={'export_date': export_data['export_date']},
        description='User requested data export (GDPR)'
    )

    # Return as downloadable JSON file
    response = Response(
        json.dumps(export_data, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=sailfishos_data_export_{current_user.username}_{datetime.utcnow().strftime("%Y%m%d")}.json'
        }
    )
    return response


# ============ Password Change ============

@dashboard_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
@check_not_banned
def change_password():
    """Allow users to change their password."""
    form = PasswordChangeForm()

    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            LogManager.log_security_event(
                LogManager.SECURITY_LOGIN_FAILED,
                username=current_user.username,
                description='Failed password change attempt - incorrect current password'
            )
            flash('Current password is incorrect.', 'danger')
            return render_template('dashboard/change_password.html', form=form)

        # Update password
        from app.models import User
        new_hash = User.hash_password(form.new_password.data)
        DataManager.update_user_password(current_user.id, new_hash)

        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='password_changed',
            entity_type='user',
            entity_id=current_user.id,
            old_data=None,
            new_data=None,  # Don't log password data
            description='User changed their password'
        )

        flash('Your password has been changed successfully.', 'success')
        return redirect(url_for('dashboard.profile'))

    return render_template('dashboard/change_password.html', form=form)


# ============ Two-Factor Authentication (2FA) ============

@dashboard_bp.route('/profile/2fa/setup', methods=['GET', 'POST'])
@login_required
@check_not_banned
def setup_2fa():
    """Set up two-factor authentication."""
    if not is_totp_available():
        flash('Two-factor authentication is not available. Required libraries are missing.', 'danger')
        return redirect(url_for('dashboard.profile'))

    if current_user.totp_enabled:
        flash('Two-factor authentication is already enabled.', 'info')
        return redirect(url_for('dashboard.profile'))

    form = TwoFactorSetupForm()

    # Generate or retrieve pending secret from session
    if 'pending_totp_secret' not in session:
        session['pending_totp_secret'] = generate_totp_secret()

    secret = session['pending_totp_secret']
    qr_code = generate_totp_qr_code(secret, current_user.username)
    totp_uri = get_totp_uri(secret, current_user.username)

    if form.validate_on_submit():
        if verify_totp(secret, form.totp_code.data):
            # Enable 2FA for the user
            DataManager.update_user(
                current_user.id,
                totp_secret=secret,
                totp_enabled=True
            )
            session.pop('pending_totp_secret', None)

            LogManager.log_action(
                user_id=current_user.id,
                username=current_user.username,
                action='2fa_enabled',
                entity_type='user',
                entity_id=current_user.id,
                old_data={'totp_enabled': False},
                new_data={'totp_enabled': True},
                description='Enabled two-factor authentication'
            )

            flash('Two-factor authentication has been enabled successfully!', 'success')
            return redirect(url_for('dashboard.profile'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template(
        'dashboard/setup_2fa.html',
        form=form,
        qr_code=qr_code,
        secret=secret,
        totp_uri=totp_uri
    )


@dashboard_bp.route('/profile/2fa/disable', methods=['GET', 'POST'])
@login_required
@check_not_banned
def disable_2fa():
    """Disable two-factor authentication."""
    if not current_user.totp_enabled:
        flash('Two-factor authentication is not enabled.', 'info')
        return redirect(url_for('dashboard.profile'))

    form = TwoFactorDisableForm()

    if form.validate_on_submit():
        # Verify password
        if not current_user.check_password(form.password.data):
            flash('Incorrect password.', 'danger')
            return render_template('dashboard/disable_2fa.html', form=form)

        # Verify TOTP code
        if not verify_totp(current_user.totp_secret, form.totp_code.data):
            flash('Invalid authentication code.', 'danger')
            return render_template('dashboard/disable_2fa.html', form=form)

        # Disable 2FA
        DataManager.update_user(
            current_user.id,
            totp_secret=None,
            totp_enabled=False
        )

        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='2fa_disabled',
            entity_type='user',
            entity_id=current_user.id,
            old_data={'totp_enabled': True},
            new_data={'totp_enabled': False},
            description='Disabled two-factor authentication'
        )

        flash('Two-factor authentication has been disabled.', 'success')
        return redirect(url_for('dashboard.profile'))

    return render_template('dashboard/disable_2fa.html', form=form)


@dashboard_bp.route('/profile/2fa/cancel')
@login_required
@check_not_banned
def cancel_2fa_setup():
    """Cancel 2FA setup."""
    session.pop('pending_totp_secret', None)
    flash('Two-factor authentication setup cancelled.', 'info')
    return redirect(url_for('dashboard.profile'))


@dashboard_bp.route('/apps')
@login_required
@check_not_banned
def apps_list():
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Limit apps per page

    category_filter = request.args.get('category', '')

    # Get paginated apps
    apps, total = DataManager.get_apps_paginated(
        page=page,
        per_page=per_page,
        category_filter=category_filter if category_filter else None
    )

    categories = DataManager.get_categories()
    category_map = {c['slug']: c for c in categories}

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'dashboard/apps_list.html',
        apps=apps,
        category_map=category_map,
        page=page,
        total_pages=total_pages,
        total=total
    )


@dashboard_bp.route('/apps/add', methods=['GET', 'POST'])
@login_required
@check_not_banned
@has_permission(CAN_ADD_APP)
def apps_add():
    categories = DataManager.get_categories()
    form = AppForm()
    form.category.choices = [(c['slug'], c['name']) for c in categories]

    if form.validate_on_submit():
        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            flash('Please complete the captcha verification.', 'danger')
            return render_template('dashboard/apps_form.html', form=form, title='Add App', reports=[], hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Parse additional native apps JSON
        additional_native_apps = []
        if form.additional_native_apps.data and form.additional_native_apps.data.strip():
            try:
                additional_native_apps = json.loads(form.additional_native_apps.data)
                if not isinstance(additional_native_apps, list):
                    flash('Invalid JSON format: expected a list of native apps.', 'danger')
                    return render_template('dashboard/apps_form.html', form=form, title='Add App', reports=[], hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])
            except json.JSONDecodeError as e:
                flash(f'Invalid JSON format for additional native apps: {e}', 'danger')
                return render_template('dashboard/apps_form.html', form=form, title='Add App', reports=[], hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        # Derive primary native app from first entry in additional_native_apps
        native_exists = len(additional_native_apps) > 0
        first_native = additional_native_apps[0] if native_exists else {}

        app_data = {
            'android_name': form.android_name.data,
            'android_package': form.android_package.data,
            'android_description': form.android_description.data,
            'android_icon_url': form.android_icon_url.data,
            'category': form.category.data,
            'countries': form.countries.data or [],
            'native_exists': native_exists,
            'native_name': first_native.get('name', ''),
            'native_store_url': first_native.get('store_url', ''),
            'native_rating': first_native.get('rating', 'none'),
            'additional_native_apps': additional_native_apps[1:] if len(additional_native_apps) > 1 else [],
            'reports_count': 0
        }
        new_app = DataManager.add_app(app_data)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_APP_ADDED,
            entity_type='app',
            entity_id=new_app.get('id'),
            old_data=None,
            new_data=new_app,
            description=f'Added app: {new_app.get("android_name")}'
        )

        flash('App added successfully.', 'success')
        return redirect(url_for('dashboard.apps_list'))

    return render_template('dashboard/apps_form.html', form=form, title='Add App', reports=[], hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@dashboard_bp.route('/apps/edit/<app_id>', methods=['GET', 'POST'])
@login_required
@check_not_banned
@has_permission(CAN_EDIT_APP)
def apps_edit(app_id):
    app = DataManager.get_app_by_id(app_id)
    if not app:
        flash('App not found.', 'danger')
        return redirect(url_for('dashboard.apps_list'))

    # Store old data for logging
    old_app_data = dict(app)

    categories = DataManager.get_categories()
    form = AppForm()
    form.category.choices = [(c['slug'], c['name']) for c in categories]

    if form.validate_on_submit():
        # Parse additional native apps JSON
        additional_native_apps = []
        if form.additional_native_apps.data and form.additional_native_apps.data.strip():
            try:
                additional_native_apps = json.loads(form.additional_native_apps.data)
                if not isinstance(additional_native_apps, list):
                    flash('Invalid JSON format: expected a list of native apps.', 'danger')
                    reports = DataManager.get_reports_for_app(app_id)
                    return render_template('dashboard/apps_form.html', form=form, title='Edit App', app=app, reports=reports)
            except json.JSONDecodeError as e:
                flash(f'Invalid JSON format for additional native apps: {e}', 'danger')
                reports = DataManager.get_reports_for_app(app_id)
                return render_template('dashboard/apps_form.html', form=form, title='Edit App', app=app, reports=reports)

        # Derive primary native app from first entry in additional_native_apps
        native_exists = len(additional_native_apps) > 0
        first_native = additional_native_apps[0] if native_exists else {}

        app_data = {
            'android_name': form.android_name.data,
            'android_package': form.android_package.data,
            'android_description': form.android_description.data,
            'android_icon_url': form.android_icon_url.data,
            'category': form.category.data,
            'countries': form.countries.data or [],
            'native_exists': native_exists,
            'native_name': first_native.get('name', ''),
            'native_store_url': first_native.get('store_url', ''),
            'native_rating': first_native.get('rating', 'none'),
            'additional_native_apps': additional_native_apps[1:] if len(additional_native_apps) > 1 else [],
            'reports_count': app.get('reports_count', 0)
        }
        updated_app = DataManager.update_app(app_id, app_data)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_APP_EDITED,
            entity_type='app',
            entity_id=app_id,
            old_data=old_app_data,
            new_data=updated_app,
            description=f'Edited app: {updated_app.get("android_name")}'
        )

        flash('App updated successfully.', 'success')
        return redirect(url_for('dashboard.apps_list'))

    reports = DataManager.get_reports_for_app(app_id)
    form.android_name.data = app.get('android_name', '')
    form.android_package.data = app.get('android_package', '')
    form.android_description.data = app.get('android_description', '')
    form.android_icon_url.data = app.get('android_icon_url', '')
    form.category.data = app.get('category', '')
    form.countries.data = app.get('countries', [])

    # Merge primary native app with additional_native_apps for the form
    all_native_apps = []
    if app.get('native_exists') and app.get('native_name'):
        all_native_apps.append({
            'name': app.get('native_name', ''),
            'store_url': app.get('native_store_url', ''),
            'rating': app.get('native_rating', 0)
        })
    all_native_apps.extend(app.get('additional_native_apps', []))
    form.additional_native_apps.data = json.dumps(all_native_apps) if all_native_apps else '[]'

    return render_template(
        'dashboard/apps_form.html',
        form=form,
        title='Edit App',
        app=app,
        reports=reports
    )


@dashboard_bp.route('/apps/delete/<app_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_DELETE_APP)
def apps_delete(app_id):
    # Get app data before deletion for logging
    app = DataManager.get_app_by_id(app_id)
    if not app:
        flash('App not found.', 'danger')
        return redirect(url_for('dashboard.apps_list'))

    old_app_data = dict(app)
    DataManager.delete_app(app_id)

    # Log the action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action=LogManager.ACTION_APP_DELETED,
        entity_type='app',
        entity_id=app_id,
        old_data=old_app_data,
        new_data=None,
        description=f'Deleted app: {old_app_data.get("android_name")}'
    )

    flash('App deleted successfully.', 'success')
    return redirect(url_for('dashboard.apps_list'))


@dashboard_bp.route('/categories')
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_CATEGORIES)
def categories_list():
    categories = DataManager.get_categories()
    return render_template('dashboard/categories_list.html', categories=categories)


@dashboard_bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_CATEGORIES)
def categories_add():
    form = CategoryForm()

    if form.validate_on_submit():
        categories = DataManager.get_categories()
        new_category = {
            'name': form.name.data,
            'slug': form.slug.data,
            'icon': form.icon.data or 'fa-mobile-alt'
        }
        categories.append(new_category)
        DataManager.save_categories(categories)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_CATEGORY_ADDED,
            entity_type='category',
            entity_id=new_category['slug'],
            old_data=None,
            new_data=new_category,
            description=f'Added category: {new_category["name"]}'
        )

        flash('Category added successfully.', 'success')
        return redirect(url_for('dashboard.categories_list'))

    return render_template('dashboard/categories_form.html', form=form, title='Add Category')


@dashboard_bp.route('/categories/edit/<slug>', methods=['GET', 'POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_CATEGORIES)
def categories_edit(slug):
    categories = DataManager.get_categories()
    category = next((c for c in categories if c['slug'] == slug), None)

    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('dashboard.categories_list'))

    # Store old data for logging
    old_category_data = dict(category)

    form = CategoryForm()

    if form.validate_on_submit():
        new_category_data = {
            'name': form.name.data,
            'slug': form.slug.data,
            'icon': form.icon.data or 'fa-mobile-alt'
        }
        for i, c in enumerate(categories):
            if c['slug'] == slug:
                categories[i] = new_category_data
                break
        DataManager.save_categories(categories)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_CATEGORY_EDITED,
            entity_type='category',
            entity_id=slug,
            old_data=old_category_data,
            new_data=new_category_data,
            description=f'Edited category: {new_category_data["name"]}'
        )

        flash('Category updated successfully.', 'success')
        return redirect(url_for('dashboard.categories_list'))

    form.name.data = category['name']
    form.slug.data = category['slug']
    form.icon.data = category.get('icon', '')

    return render_template('dashboard/categories_form.html', form=form, title='Edit Category')


@dashboard_bp.route('/categories/delete/<slug>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_CATEGORIES)
def categories_delete(slug):
    categories = DataManager.get_categories()
    category = next((c for c in categories if c['slug'] == slug), None)

    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('dashboard.categories_list'))

    old_category_data = dict(category)
    categories = [c for c in categories if c['slug'] != slug]
    DataManager.save_categories(categories)

    # Log the action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action=LogManager.ACTION_CATEGORY_DELETED,
        entity_type='category',
        entity_id=slug,
        old_data=old_category_data,
        new_data=None,
        description=f'Deleted category: {old_category_data["name"]}'
    )

    flash('Category deleted successfully.', 'success')
    return redirect(url_for('dashboard.categories_list'))


@dashboard_bp.route('/reports')
@login_required
@check_not_banned
def reports_list():
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Limit reports per page

    apps = DataManager.get_apps()
    app_map = {app['id']: app for app in apps}

    # Regular users only see their own reports
    # Moderators and admins see all reports
    if not check_permission(current_user, CAN_DELETE_REPORT):
        reports, total = DataManager.get_reports_paginated(
            page=page,
            per_page=per_page,
            user_id=current_user.id
        )
    else:
        reports, total = DataManager.get_reports_paginated(
            page=page,
            per_page=per_page,
            user_id=None
        )

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'dashboard/reports_list.html',
        reports=reports,
        app_map=app_map,
        page=page,
        total_pages=total_pages,
        total=total
    )


@dashboard_bp.route('/reports/delete/<report_id>', methods=['POST'])
@login_required
@check_not_banned
def reports_delete(report_id):
    # Get report data before deletion for logging
    reports = DataManager.get_reports()
    report = next((r for r in reports if r.get('id') == report_id), None)

    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard.reports_list'))

    # Check permission: user can delete own reports, moderators+ can delete any
    is_own_report = report.get('user_id') == current_user.id
    can_delete_any = check_permission(current_user, CAN_DELETE_REPORT)

    if not is_own_report and not can_delete_any:
        flash('You do not have permission to delete this report.', 'danger')
        return redirect(url_for('dashboard.reports_list'))

    old_report_data = dict(report)
    deleted = DataManager.delete_report(report_id)

    if deleted:
        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_REPORT_DELETED,
            entity_type='report',
            entity_id=report_id,
            old_data=old_report_data,
            new_data=None,
            description=f'Deleted report for app {old_report_data.get("app_id", "unknown")}'
        )
        flash('Report deleted successfully.', 'success')
    else:
        flash('Report not found.', 'danger')
    return redirect(url_for('dashboard.reports_list'))


@dashboard_bp.route('/reports/edit/<report_id>', methods=['GET', 'POST'])
@login_required
@check_not_banned
def reports_edit(report_id):
    """Edit a report - users can edit their own reports."""
    reports = DataManager.get_reports()
    report = next((r for r in reports if r.get('id') == report_id), None)

    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard.reports_list'))

    # Check permission: user can edit own reports, moderators+ can edit any
    is_own_report = report.get('user_id') == current_user.id
    can_edit_any = check_permission(current_user, CAN_DELETE_REPORT)

    if not is_own_report and not can_edit_any:
        flash('You do not have permission to edit this report.', 'danger')
        return redirect(url_for('dashboard.reports_list'))

    # Store old data for logging
    old_report_data = dict(report)

    # Get app info for display
    app = DataManager.get_app_by_id(report.get('app_id'))

    form = ReportForm()
    native_app_choices = [('', '-- Select native app --')]
    native_names = []
    if app and app.get('native_exists') and app.get('native_name'):
        native_names.append(app.get('native_name'))
    if app:
        for native_app in app.get('additional_native_apps', []):
            name = native_app.get('name')
            if name:
                native_names.append(name)
    for name in native_names:
        if name not in [choice[0] for choice in native_app_choices]:
            native_app_choices.append((name, name))
    native_app_choices.append(('custom', 'Custom...'))
    form.native_app.choices = native_app_choices

    if form.validate_on_submit():
        # Update report data
        report['platform'] = form.platform.data
        report['works'] = form.works.data
        report['dependency'] = form.dependency.data if form.platform.data == 'android' else None
        report['native_app_name'] = (
            (form.custom_native_app.data or '').strip()
            if form.platform.data == 'native' and form.native_app.data == 'custom'
            else (form.native_app.data or None) if form.platform.data == 'native' else None
        )
        report['device'] = form.custom_device.data if form.device.data == 'custom' else form.device.data
        report['sailfish_version'] = form.custom_sailfish_version.data if form.sailfish_version.data == 'custom' else form.sailfish_version.data
        report['app_version'] = form.app_version.data
        report['notes'] = form.notes.data

        # Save updated reports
        DataManager.save_reports(reports)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_REPORT_EDITED,
            entity_type='report',
            entity_id=report_id,
            old_data=old_report_data,
            new_data=report,
            description=f'Edited report for app {report.get("app_id", "unknown")}'
        )

        flash('Report updated successfully.', 'success')
        return redirect(url_for('dashboard.reports_list'))

    # Pre-populate form
    form.platform.data = report.get('platform', '')
    form.works.data = report.get('works', '')
    form.dependency.data = report.get('dependency', '')
    stored_native_app = (report.get('native_app_name') or '').strip()
    native_choice_values = [choice[0] for choice in form.native_app.choices]
    if stored_native_app and stored_native_app in native_choice_values:
        form.native_app.data = stored_native_app
    elif stored_native_app:
        form.native_app.data = 'custom'
        form.custom_native_app.data = stored_native_app
    else:
        form.native_app.data = ''
    # Check if device is in the standard list or a custom one
    stored_device = report.get('device', '')
    standard_devices = [d[0] for d in SUPPORTED_DEVICES if d[0] and d[0] != 'custom']
    if stored_device in standard_devices:
        form.device.data = stored_device
    elif stored_device:
        form.device.data = 'custom'
        form.custom_device.data = stored_device
    else:
        form.device.data = ''
    # Check if SFOS version is in the standard list or a custom one
    stored_sfos = report.get('sailfish_version', '')
    standard_sfos = [v[0] for v in SFOS_VERSIONS if v[0] and v[0] != 'custom']
    if stored_sfos in standard_sfos:
        form.sailfish_version.data = stored_sfos
    elif stored_sfos:
        form.sailfish_version.data = 'custom'
        form.custom_sailfish_version.data = stored_sfos
    else:
        form.sailfish_version.data = ''
    form.app_version.data = report.get('app_version', '')
    form.notes.data = report.get('notes', '')

    return render_template('dashboard/reports_form.html', form=form, report=report, app=app)


@dashboard_bp.route('/apps/fetch-info/<app_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_REFRESH_PLAYSTORE)
def fetch_app_info(app_id):
    """Fetch icon and description for a single app from Play Store."""
    app = DataManager.get_app_by_id(app_id)
    if not app:
        flash('App not found.', 'danger')
        return redirect(url_for('dashboard.apps_list'))

    package_name = app.get('android_package')
    if not package_name:
        flash('No package name set for this app. Cannot fetch info.', 'warning')
        return redirect(url_for('dashboard.apps_edit', app_id=app_id))

    # Check if this is a full refresh (force overwrite)
    force_refresh = request.form.get('force') == '1'

    # Clear old icon path if it uses the deprecated location
    current_icon = app.get('android_icon_url', '')
    if current_icon.startswith('/static/icons/'):
        app['android_icon_url'] = ''

    info = fetch_and_update_app_info(package_name)

    if info:
        updated = []

        # Update icon if we got a local path
        if info.get('local_icon_path'):
            if force_refresh or not app.get('android_icon_url'):
                app['android_icon_url'] = info['local_icon_path']
                updated.append('icon')
        elif info.get('icon_url'):
            if force_refresh or not app.get('android_icon_url'):
                app['android_icon_url'] = info['icon_url']
                updated.append('icon (remote)')

        # Update description
        if info.get('description'):
            current_desc = app.get('android_description', '')
            if force_refresh or not current_desc or len(info['description']) > len(current_desc):
                app['android_description'] = info['description'][:500]
                updated.append('description')

        # Update name if force refresh
        if force_refresh and info.get('name'):
            app['android_name'] = info['name']
            updated.append('name')

        if updated:
            DataManager.update_app(app_id, app)
            flash(f'Updated: {", ".join(updated)}', 'success')
        else:
            flash('No new information to update.', 'info')
    else:
        flash(f'Could not fetch info for {package_name}. App may not be on Play Store.', 'danger')

    return redirect(url_for('dashboard.apps_edit', app_id=app_id))


@dashboard_bp.route('/apps/fetch-all-info', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_REFRESH_PLAYSTORE)
def fetch_all_info():
    """Fetch icons and descriptions for all apps from Play Store."""
    apps = DataManager.get_apps()
    success_count = 0
    fail_count = 0
    skip_count = 0

    # Check if this is a full refresh (force overwrite)
    force_refresh = request.form.get('force') == '1'

    for app in apps:
        package_name = app.get('android_package')
        if not package_name:
            skip_count += 1
            continue

        # Clear old icon path if it uses the deprecated location
        current_icon = app.get('android_icon_url', '')
        if current_icon.startswith('/static/icons/'):
            app['android_icon_url'] = ''

        has_icon = bool(app.get('android_icon_url'))
        has_desc = bool(app.get('android_description'))

        # Skip if already has valid icon and description (unless force refresh)
        if not force_refresh and has_icon and has_desc:
            skip_count += 1
            continue

        info = fetch_and_update_app_info(package_name)

        if info:
            updated = False

            # Update icon
            if info.get('local_icon_path'):
                if force_refresh or not has_icon:
                    app['android_icon_url'] = info['local_icon_path']
                    updated = True
            elif info.get('icon_url'):
                if force_refresh or not has_icon:
                    app['android_icon_url'] = info['icon_url']
                    updated = True

            # Update description
            if info.get('description'):
                current_desc = app.get('android_description', '')
                if force_refresh or not current_desc or len(info['description']) > len(current_desc):
                    app['android_description'] = info['description'][:500]
                    updated = True

            # Update name if force refresh
            if force_refresh and info.get('name'):
                app['android_name'] = info['name']
                updated = True

            if updated:
                DataManager.update_app(app['id'], app)
                success_count += 1
            else:
                skip_count += 1
        else:
            fail_count += 1

    flash(f'Info fetched: {success_count} updated, {fail_count} failed, {skip_count} skipped.', 'info')
    return redirect(url_for('dashboard.apps_list'))


# ============ User Management (Admin Only) ============

@dashboard_bp.route('/users')
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_USERS)
def users_list():
    """Admin view to manage users with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Limit users per page to prevent performance issues

    # Get filters
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')

    # Get paginated users
    users, total = DataManager.get_users_paginated(
        page=page,
        per_page=per_page,
        role_filter=role_filter if role_filter else None,
        status_filter=status_filter if status_filter else None
    )

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'dashboard/users_list.html',
        users=users,
        page=page,
        total_pages=total_pages,
        total=total
    )


@dashboard_bp.route('/users/ban/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_USERS)
def users_ban(user_id):
    """Ban a user."""
    user = DataManager.get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    if user.id == current_user.id:
        flash('You cannot ban yourself.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    if user.role == 'admin':
        flash('You cannot ban an admin.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    DataManager.update_user(user_id, is_banned=True)

    # Log the action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action=LogManager.ACTION_USER_BANNED,
        entity_type='user',
        entity_id=user_id,
        old_data={'username': user.username, 'is_banned': False},
        new_data={'username': user.username, 'is_banned': True},
        description=f'Banned user: {user.username}'
    )

    flash(f'User {user.username} has been banned.', 'success')
    return redirect(url_for('dashboard.users_list'))


@dashboard_bp.route('/users/unban/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_USERS)
def users_unban(user_id):
    """Unban a user."""
    user = DataManager.get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    DataManager.update_user(user_id, is_banned=False)

    # Log the action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action=LogManager.ACTION_USER_UNBANNED,
        entity_type='user',
        entity_id=user_id,
        old_data={'username': user.username, 'is_banned': True},
        new_data={'username': user.username, 'is_banned': False},
        description=f'Unbanned user: {user.username}'
    )

    flash(f'User {user.username} has been unbanned.', 'success')
    return redirect(url_for('dashboard.users_list'))


@dashboard_bp.route('/users/set-role/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_MANAGE_USERS)
def users_set_role(user_id):
    """Change user role."""
    user = DataManager.get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    if user.id == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    new_role = request.form.get('role', 'user')
    if new_role not in ('user', 'moderator', 'admin'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    old_role = user.role
    DataManager.update_user(user_id, role=new_role)

    # Log the role change
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action=LogManager.ACTION_USER_ROLE_CHANGED,
        entity_type='user',
        entity_id=user_id,
        old_data={'username': user.username, 'role': old_role},
        new_data={'username': user.username, 'role': new_role},
        description=f'Changed role from {old_role} to {new_role}'
    )

    flash(f'User {user.username} role changed to {new_role}.', 'success')
    return redirect(url_for('dashboard.users_list'))


# ============ Admin Backup ============

@dashboard_bp.route('/backup')
@login_required
@check_not_banned
@has_permission(CAN_VIEW_LOGS)  # Only admins can create backups
def admin_backup():
    """Export all system data for backup purposes."""
    backup_data = DataManager.export_full_backup()

    # Log the backup action
    LogManager.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='backup_created',
        entity_type='system',
        entity_id=None,
        old_data=None,
        new_data={'backup_date': backup_data['backup_date'], 'statistics': backup_data['statistics']},
        description=f'Admin created system backup'
    )

    # Return as downloadable JSON file
    response = Response(
        json.dumps(backup_data, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=sailfishos_backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        }
    )
    return response


# ============ Audit Logs (Admin Only) ============

@dashboard_bp.route('/logs')
@login_required
@check_not_banned
@has_permission(CAN_VIEW_LOGS)
def logs_list():
    """View audit logs."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    action_filter = request.args.get('action', '')
    entity_type_filter = request.args.get('entity_type', '')

    logs, total = LogManager.get_logs(
        limit=per_page,
        offset=(page - 1) * per_page,
        action_filter=action_filter if action_filter else None,
        entity_type_filter=entity_type_filter if entity_type_filter else None
    )

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'dashboard/logs.html',
        logs=logs,
        page=page,
        total_pages=total_pages,
        total=total
    )


@dashboard_bp.route('/logs/rollback/<log_id>', methods=['POST'])
@login_required
@check_not_banned
@has_permission(CAN_ROLLBACK)
def logs_rollback(log_id):
    """Rollback an action."""
    log = LogManager.get_log_by_id(log_id)
    if not log:
        flash('Log entry not found.', 'danger')
        return redirect(url_for('dashboard.logs_list'))

    if log.get('rolled_back'):
        flash('This action has already been rolled back.', 'warning')
        return redirect(url_for('dashboard.logs_list'))

    action = log.get('action')
    entity_type = log.get('entity_type')
    entity_id = log.get('entity_id')
    old_data = log.get('old_data')

    # Validate rollback data before proceeding
    is_valid, error_message = DataManager.validate_rollback_data(entity_type, old_data)
    if not is_valid:
        flash(f'Cannot rollback: {error_message}', 'danger')
        return redirect(url_for('dashboard.logs_list'))

    success = False

    # Handle rollback based on action type
    if action == LogManager.ACTION_APP_EDITED and old_data:
        # Restore previous app state
        DataManager.update_app(entity_id, old_data)
        success = True

    elif action == LogManager.ACTION_APP_DELETED and old_data:
        # Restore deleted app
        apps = DataManager.get_apps()
        old_data['id'] = entity_id
        apps.append(old_data)
        DataManager.save_apps(apps)
        success = True

    elif action == LogManager.ACTION_REPORT_DELETED and old_data:
        # Restore deleted report
        reports = DataManager.get_reports()
        old_data['id'] = entity_id
        reports.append(old_data)
        DataManager.save_reports(reports)
        # Increment app reports count
        if old_data.get('app_id'):
            DataManager._increment_app_reports_count(old_data['app_id'])
        success = True

    elif action == LogManager.ACTION_CATEGORY_EDITED and old_data:
        # Restore previous category state
        categories = DataManager.get_categories()
        for i, c in enumerate(categories):
            if c.get('slug') == entity_id or c.get('slug') == old_data.get('slug'):
                categories[i] = old_data
                break
        DataManager.save_categories(categories)
        success = True

    elif action == LogManager.ACTION_CATEGORY_DELETED and old_data:
        # Restore deleted category
        categories = DataManager.get_categories()
        categories.append(old_data)
        DataManager.save_categories(categories)
        success = True

    if success:
        # Mark as rolled back
        LogManager.mark_as_rolled_back(log_id, current_user.id, current_user.username)

        # Log the rollback action
        LogManager.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action=LogManager.ACTION_ROLLBACK,
            entity_type=entity_type,
            entity_id=entity_id,
            old_data=None,
            new_data=old_data,
            description=f'Rolled back {action} for {entity_type}'
        )

        flash('Action has been rolled back successfully.', 'success')
    else:
        flash('This action cannot be rolled back.', 'danger')

    return redirect(url_for('dashboard.logs_list'))
