from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, send_from_directory
from flask_login import current_user
from app import limiter
from app.models import DataManager
from app.forms import SearchForm, ReportForm, AppSubmitForm
from app.utils import fetch_and_update_app_info, verify_hcaptcha
from app.logs import LogManager
from config import Config

frontend_bp = Blueprint('frontend', __name__)


@frontend_bp.route('/icons/<path:filename>')
def serve_icon(filename):
    """Serve icons from the data/icons directory."""
    return send_from_directory(Config.ICONS_DIR, filename)


@frontend_bp.route('/')
def index():
    apps = DataManager.get_apps()
    categories = DataManager.get_categories()

    # CSRF disabled for search form: this is a GET request for filtering/searching
    # which is idempotent and doesn't modify state, so CSRF protection is not needed
    form = SearchForm(request.args, meta={'csrf': False})
    form.category.choices = [('', 'All Categories')] + [(c['slug'], c['name']) for c in categories]

    q = request.args.get('q', '').strip().lower()
    category = request.args.get('category', '')
    status = request.args.get('status', '')
    country = request.args.get('country', '')

    filtered_apps = apps

    if q:
        filtered_apps = [
            app for app in filtered_apps
            if q in app.get('android_name', '').lower() or
               q in app.get('android_description', '').lower()
        ]

    if category:
        filtered_apps = [
            app for app in filtered_apps
            if app.get('category') == category
        ]

    if country:
        filtered_apps = [
            app for app in filtered_apps
            if country in app.get('countries', []) or 'GLOBAL' in app.get('countries', [])
        ]

    if status:
        if status == 'native':
            filtered_apps = [
                app for app in filtered_apps
                if app.get('native_exists', False)
            ]

    # Sort apps: has native app, has rating, rating quality, then alphabetically
    ratings_map = {}
    for app in filtered_apps:
        rating, count = DataManager.get_app_rating_from_reports(app['id'])
        ratings_map[app['id']] = {'rating': rating, 'count': count}

    def sort_key(app):
        rating_info = ratings_map.get(app['id'], {'rating': 0, 'count': 0})
        has_native = 1 if app.get('native_exists') else 0
        has_rating = 1 if rating_info['rating'] > 0 else 0
        rating_value = rating_info['rating'] or 0
        return (-has_native, -has_rating, -rating_value, -rating_info['count'], app.get('android_name', '').lower())

    filtered_apps.sort(key=sort_key)

    page = request.args.get('page', 1, type=int)
    per_page = 20
    total = len(filtered_apps)
    total_pages = (total + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    paginated_apps = filtered_apps[start:end]

    category_map = {c['slug']: c for c in categories}

    # Calculate ratings from community reports for each app
    app_ratings = {}
    for app in paginated_apps:
        rating_info = ratings_map.get(app['id'])
        rating = rating_info['rating'] if rating_info else 0
        count = rating_info['count'] if rating_info else 0
        community_status = DataManager.get_app_status_from_reports(app['id'])
        platform_ratings = DataManager.get_app_ratings_by_platform(app['id'])
        app_ratings[app['id']] = {
            'rating': rating,
            'count': count,
            'status': community_status,
            'platforms': platform_ratings
        }

    return render_template(
        'frontend/index.html',
        apps=paginated_apps,
        categories=categories,
        category_map=category_map,
        form=form,
        page=page,
        total_pages=total_pages,
        total=total,
        app_ratings=app_ratings
    )


@frontend_bp.route('/app/<app_id>', methods=['GET', 'POST'])
@limiter.limit("20 per hour", methods=["POST"])  # Rate limit report submissions
def app_detail(app_id):
    app = DataManager.get_app_by_id(app_id)
    categories = DataManager.get_categories()
    category_map = {c['slug']: c for c in categories}

    if not app:
        return render_template('frontend/404.html'), 404

    form = ReportForm()
    native_app_choices = [('', '-- Select native app --')]
    native_names = []
    if app.get('native_exists') and app.get('native_name'):
        native_names.append(app.get('native_name'))
    for native_app in app.get('additional_native_apps', []):
        name = native_app.get('name')
        if name:
            native_names.append(name)
    for name in native_names:
        if name not in [choice[0] for choice in native_app_choices]:
            native_app_choices.append((name, name))
    native_app_choices.append(('custom', 'Custom...'))
    form.native_app.choices = native_app_choices
    reports = DataManager.get_reports_for_app(app_id)

    # Calculate rating from community reports
    community_rating, report_count = DataManager.get_app_rating_from_reports(app_id)
    community_status = DataManager.get_app_status_from_reports(app_id)
    platform_ratings = DataManager.get_app_ratings_by_platform(app_id)

    if form.validate_on_submit():
        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            flash('Please complete the captcha verification.', 'danger')
            return render_template(
                'frontend/app_detail.html',
                app=app,
                category_map=category_map,
                form=form,
                reports=reports,
                hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'],
                community_rating=community_rating,
                community_status=community_status,
                report_count=report_count,
                platform_ratings=platform_ratings
            )

        # Save the report
        report_data = {
            'app_id': app_id,
            'reporter_name': form.reporter_name.data or 'Anonymous',
            'platform': form.platform.data,
            'works': form.works.data,
            'dependency': form.dependency.data if form.platform.data == 'android' else None,
            'native_app_name': (
                (form.custom_native_app.data or '').strip()
                if form.platform.data == 'native' and form.native_app.data == 'custom'
                else (form.native_app.data or None) if form.platform.data == 'native' else None
            ),
            'device': form.custom_device.data if form.device.data == 'custom' else form.device.data,
            'sailfish_version': form.custom_sailfish_version.data if form.sailfish_version.data == 'custom' else form.sailfish_version.data,
            'app_version': form.app_version.data,
            'notes': form.notes.data,
            'user_id': current_user.id if current_user.is_authenticated else None
        }

        new_report = DataManager.add_report(report_data)

        # Log the action
        LogManager.log_action(
            user_id=current_user.id if current_user.is_authenticated else None,
            username=current_user.username if current_user.is_authenticated else report_data.get('reporter_name', 'Anonymous'),
            action=LogManager.ACTION_REPORT_ADDED,
            entity_type='report',
            entity_id=new_report.get('id'),
            old_data=None,
            new_data=new_report,
            description=f'Report submitted for app {app_id}'
        )

        flash('Thank you! Your report has been submitted.', 'success')
        return redirect(url_for('frontend.app_detail', app_id=app_id))

    return render_template(
        'frontend/app_detail.html',
        app=app,
        category_map=category_map,
        form=form,
        reports=reports,
        hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY'],
        community_rating=community_rating,
        community_status=community_status,
        report_count=report_count,
        platform_ratings=platform_ratings
    )


@frontend_bp.route('/about')
def about():
    return render_template('frontend/about.html')


@frontend_bp.route('/submit-app', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])  # Rate limit app submissions
def submit_app():
    """Allow anyone to submit a new app by package name."""
    categories = DataManager.get_categories()
    form = AppSubmitForm()
    form.category.choices = [(c['slug'], c['name']) for c in categories]

    if form.validate_on_submit():
        package_name = form.android_package.data.strip()

        # Check if app already exists
        existing = DataManager.get_app_by_package(package_name)
        if existing:
            flash(f'This app is already in our database.', 'info')
            return redirect(url_for('frontend.app_detail', app_id=existing['id']))

        # Verify hCaptcha
        hcaptcha_response = request.form.get('h-captcha-response')
        if not verify_hcaptcha(hcaptcha_response):
            flash('Please complete the captcha verification.', 'danger')
            return render_template(
                'frontend/submit_app.html',
                form=form,
                hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY']
            )

        # Fetch info from Play Store
        info = fetch_and_update_app_info(package_name)

        if not info or not info.get('name'):
            flash(f'Could not find app "{package_name}" on Play Store. Please check the package name.', 'danger')
            return render_template(
                'frontend/submit_app.html',
                form=form,
                hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY']
            )

        # Create new app entry
        app_data = {
            'android_name': info.get('name', package_name),
            'android_package': package_name,
            'android_description': (info.get('description', '') or '')[:500],
            'android_icon_url': info.get('local_icon_path') or info.get('icon_url', ''),
            'category': form.category.data,
            'countries': [],
            'native_exists': False,
            'native_name': '',
            'native_store_url': '',
            'native_rating': 'none',
            'additional_native_apps': [],
            'reports_count': 0
        }

        new_app = DataManager.add_app(app_data)
        flash(f'App "{app_data["android_name"]}" has been added! You can now submit a compatibility report.', 'success')
        return redirect(url_for('frontend.app_detail', app_id=new_app['id']))

    return render_template(
        'frontend/submit_app.html',
        form=form,
        hcaptcha_site_key=current_app.config['HCAPTCHA_SITE_KEY']
    )
