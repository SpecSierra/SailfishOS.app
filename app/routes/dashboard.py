import json
import requests
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app import login_manager
from app.models import DataManager, User
from app.forms import LoginForm, AppForm, CategoryForm, RegistrationForm
from app.utils import fetch_play_store_icon, fetch_and_save_icon, fetch_and_update_app_info
from app.decorators import role_required, admin_required, moderator_required, check_not_banned


def verify_hcaptcha(response_token):
    """Verify hCaptcha response token."""
    if not response_token:
        return False

    payload = {
        'secret': current_app.config['HCAPTCHA_SECRET_KEY'],
        'response': response_token
    }

    try:
        r = requests.post(current_app.config['HCAPTCHA_VERIFY_URL'], data=payload, timeout=10)
        result = r.json()
        return result.get('success', False)
    except Exception:
        return False

dashboard_bp = Blueprint('dashboard', __name__)


@login_manager.user_loader
def load_user(user_id):
    return DataManager.get_user_by_id(user_id)


@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()
    if form.validate_on_submit():
        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            flash('Please complete the captcha verification.', 'danger')
            return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])

        user = DataManager.get_user_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            if user.is_banned:
                flash('Your account has been suspended.', 'danger')
                return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash('Logged in successfully.', 'success')
            return redirect(next_page or url_for('dashboard.index'))
        flash('Invalid username or password.', 'danger')

    return render_template('dashboard/login.html', form=form, hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@dashboard_bp.route('/register', methods=['GET', 'POST'])
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
    """Delete user account."""
    user_id = current_user.id
    username = current_user.username

    # Logout first
    logout_user()

    # Delete the user
    DataManager.delete_user(user_id)

    flash(f'Account "{username}" has been deleted.', 'info')
    return redirect(url_for('frontend.index'))


@dashboard_bp.route('/apps')
@login_required
def apps_list():
    apps = DataManager.get_apps()
    categories = DataManager.get_categories()
    category_map = {c['slug']: c for c in categories}
    return render_template('dashboard/apps_list.html', apps=apps, category_map=category_map)


@dashboard_bp.route('/apps/add', methods=['GET', 'POST'])
@login_required
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
        if form.additional_native_apps.data:
            try:
                additional_native_apps = json.loads(form.additional_native_apps.data)
            except json.JSONDecodeError:
                flash('Invalid JSON format for additional native apps.', 'warning')

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
            'native_rating': int(first_native.get('rating', 0)),
            'additional_native_apps': additional_native_apps[1:] if len(additional_native_apps) > 1 else [],
            'android_support_works': form.android_support_works.data,
            'android_support_rating': int(form.android_support_rating.data),
            'android_support_notes': form.android_support_notes.data,
            'dependency': form.dependency.data,
            'browser_works': form.browser_works.data,
            'browser_notes': form.browser_notes.data,
            'reports_count': 0
        }
        DataManager.add_app(app_data)
        flash('App added successfully.', 'success')
        return redirect(url_for('dashboard.apps_list'))

    return render_template('dashboard/apps_form.html', form=form, title='Add App', reports=[], hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'])


@dashboard_bp.route('/apps/edit/<app_id>', methods=['GET', 'POST'])
@login_required
def apps_edit(app_id):
    app = DataManager.get_app_by_id(app_id)
    if not app:
        flash('App not found.', 'danger')
        return redirect(url_for('dashboard.apps_list'))

    categories = DataManager.get_categories()
    form = AppForm()
    form.category.choices = [(c['slug'], c['name']) for c in categories]

    if form.validate_on_submit():
        # Parse additional native apps JSON
        additional_native_apps = []
        if form.additional_native_apps.data:
            try:
                additional_native_apps = json.loads(form.additional_native_apps.data)
            except json.JSONDecodeError:
                flash('Invalid JSON format for additional native apps.', 'warning')

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
            'native_rating': int(first_native.get('rating', 0)),
            'additional_native_apps': additional_native_apps[1:] if len(additional_native_apps) > 1 else [],
            'android_support_works': form.android_support_works.data,
            'android_support_rating': int(form.android_support_rating.data),
            'android_support_notes': form.android_support_notes.data,
            'dependency': form.dependency.data,
            'browser_works': form.browser_works.data,
            'browser_notes': form.browser_notes.data,
            'reports_count': app.get('reports_count', 0)
        }
        DataManager.update_app(app_id, app_data)
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

    form.android_support_works.data = app.get('android_support_works', 'unknown')
    form.android_support_rating.data = str(app.get('android_support_rating', 0))
    form.android_support_notes.data = app.get('android_support_notes', '')
    form.dependency.data = app.get('dependency', 'none')
    form.browser_works.data = app.get('browser_works', 'unknown')
    form.browser_notes.data = app.get('browser_notes', '')

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
@admin_required
def apps_delete(app_id):
    DataManager.delete_app(app_id)
    flash('App deleted successfully.', 'success')
    return redirect(url_for('dashboard.apps_list'))


@dashboard_bp.route('/categories')
@login_required
def categories_list():
    categories = DataManager.get_categories()
    return render_template('dashboard/categories_list.html', categories=categories)


@dashboard_bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
def categories_add():
    form = CategoryForm()

    if form.validate_on_submit():
        categories = DataManager.get_categories()
        categories.append({
            'name': form.name.data,
            'slug': form.slug.data,
            'icon': form.icon.data or 'fa-mobile-alt'
        })
        DataManager.save_categories(categories)
        flash('Category added successfully.', 'success')
        return redirect(url_for('dashboard.categories_list'))

    return render_template('dashboard/categories_form.html', form=form, title='Add Category')


@dashboard_bp.route('/categories/edit/<slug>', methods=['GET', 'POST'])
@login_required
def categories_edit(slug):
    categories = DataManager.get_categories()
    category = next((c for c in categories if c['slug'] == slug), None)

    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('dashboard.categories_list'))

    form = CategoryForm()

    if form.validate_on_submit():
        for i, c in enumerate(categories):
            if c['slug'] == slug:
                categories[i] = {
                    'name': form.name.data,
                    'slug': form.slug.data,
                    'icon': form.icon.data or 'fa-mobile-alt'
                }
                break
        DataManager.save_categories(categories)
        flash('Category updated successfully.', 'success')
        return redirect(url_for('dashboard.categories_list'))

    form.name.data = category['name']
    form.slug.data = category['slug']
    form.icon.data = category.get('icon', '')

    return render_template('dashboard/categories_form.html', form=form, title='Edit Category')


@dashboard_bp.route('/categories/delete/<slug>', methods=['POST'])
@login_required
def categories_delete(slug):
    categories = DataManager.get_categories()
    categories = [c for c in categories if c['slug'] != slug]
    DataManager.save_categories(categories)
    flash('Category deleted successfully.', 'success')
    return redirect(url_for('dashboard.categories_list'))


@dashboard_bp.route('/reports')
@login_required
def reports_list():
    reports = DataManager.get_reports()
    apps = DataManager.get_apps()
    app_map = {app['id']: app for app in apps}
    reports = sorted(reports, key=lambda r: r.get('created_at', ''), reverse=True)
    return render_template('dashboard/reports_list.html', reports=reports, app_map=app_map)


@dashboard_bp.route('/reports/delete/<report_id>', methods=['POST'])
@login_required
@check_not_banned
@moderator_required
def reports_delete(report_id):
    deleted = DataManager.delete_report(report_id)
    if deleted:
        flash('Report deleted successfully.', 'success')
    else:
        flash('Report not found.', 'danger')
    return redirect(url_for('dashboard.reports_list'))


@dashboard_bp.route('/apps/fetch-info/<app_id>', methods=['POST'])
@login_required
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
@admin_required
def users_list():
    """Admin view to manage users."""
    users = DataManager.get_users()
    return render_template('dashboard/users_list.html', users=users)


@dashboard_bp.route('/users/ban/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@admin_required
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
    flash(f'User {user.username} has been banned.', 'success')
    return redirect(url_for('dashboard.users_list'))


@dashboard_bp.route('/users/unban/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@admin_required
def users_unban(user_id):
    """Unban a user."""
    user = DataManager.get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard.users_list'))

    DataManager.update_user(user_id, is_banned=False)
    flash(f'User {user.username} has been unbanned.', 'success')
    return redirect(url_for('dashboard.users_list'))


@dashboard_bp.route('/users/set-role/<user_id>', methods=['POST'])
@login_required
@check_not_banned
@admin_required
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

    DataManager.update_user(user_id, role=new_role)
    flash(f'User {user.username} role changed to {new_role}.', 'success')
    return redirect(url_for('dashboard.users_list'))
