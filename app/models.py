import json
import os
import uuid
from datetime import datetime
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app

ph = PasswordHasher()


class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role='user', is_banned=False):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.is_banned = is_banned

    def check_password(self, password):
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False

    @staticmethod
    def hash_password(password):
        return ph.hash(password)

    def has_permission(self, permission):
        """Check if user has a specific permission."""
        from app.permissions import check_permission
        return check_permission(self, permission)

    def has_any_permission(self, *permissions):
        """Check if user has any of the specified permissions."""
        from app.permissions import check_permission
        return any(check_permission(self, p) for p in permissions)

    def has_all_permissions(self, *permissions):
        """Check if user has all specified permissions."""
        from app.permissions import check_permission
        return all(check_permission(self, p) for p in permissions)

    @property
    def is_admin(self):
        """Check if user is an admin."""
        return self.role == 'admin'

    @property
    def is_moderator(self):
        """Check if user is a moderator or higher."""
        return self.role in ('admin', 'moderator')

    @property
    def role_level(self):
        """Get the numeric level for this user's role."""
        from app.permissions import get_role_level
        return get_role_level(self.role)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'role': self.role,
            'is_banned': self.is_banned
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data['id'],
            username=data['username'],
            email=data['email'],
            password_hash=data['password_hash'],
            role=data.get('role', 'user'),
            is_banned=data.get('is_banned', False)
        )


class DataManager:
    @staticmethod
    def _get_path(filename):
        return os.path.join(current_app.config['DATA_DIR'], filename)

    @staticmethod
    def _load_json(filepath):
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    @staticmethod
    def _save_json(filepath, data):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def get_apps(cls):
        data = cls._load_json(current_app.config['APPS_JSON'])
        return data.get('apps', [])

    @classmethod
    def get_app_by_id(cls, app_id):
        apps = cls.get_apps()
        for app in apps:
            if app['id'] == app_id:
                return app
        return None

    @classmethod
    def save_apps(cls, apps):
        cls._save_json(current_app.config['APPS_JSON'], {'apps': apps})

    @classmethod
    def get_app_by_package(cls, package_name):
        apps = cls.get_apps()
        for app in apps:
            if app.get('android_package', '').lower() == package_name.lower():
                return app
        return None

    @classmethod
    def add_app(cls, app_data):
        apps = cls.get_apps()
        app_data['id'] = str(uuid.uuid4())
        app_data['created_at'] = datetime.utcnow().isoformat()
        app_data['updated_at'] = datetime.utcnow().isoformat()
        apps.append(app_data)
        cls.save_apps(apps)
        return app_data

    @classmethod
    def update_app(cls, app_id, app_data):
        apps = cls.get_apps()
        for i, app in enumerate(apps):
            if app['id'] == app_id:
                app_data['id'] = app_id
                app_data['created_at'] = app.get('created_at', datetime.utcnow().isoformat())
                app_data['updated_at'] = datetime.utcnow().isoformat()
                apps[i] = app_data
                cls.save_apps(apps)
                return app_data
        return None

    @classmethod
    def delete_app(cls, app_id):
        apps = cls.get_apps()
        apps = [app for app in apps if app['id'] != app_id]
        cls.save_apps(apps)

    @classmethod
    def get_categories(cls):
        data = cls._load_json(current_app.config['CATEGORIES_JSON'])
        return data.get('categories', [])

    @classmethod
    def save_categories(cls, categories):
        cls._save_json(current_app.config['CATEGORIES_JSON'], {'categories': categories})

    @classmethod
    def get_users(cls):
        data = cls._load_json(current_app.config['USERS_JSON'])
        return [User.from_dict(u) for u in data.get('users', [])]

    @classmethod
    def get_user_by_id(cls, user_id):
        users = cls.get_users()
        for user in users:
            if user.id == user_id:
                return user
        return None

    @classmethod
    def get_user_by_username(cls, username):
        users = cls.get_users()
        for user in users:
            if user.username == username:
                return user
        return None

    @classmethod
    def save_users(cls, users):
        data = {'users': [u.to_dict() for u in users]}
        cls._save_json(current_app.config['USERS_JSON'], data)

    @classmethod
    def get_user_by_email(cls, email):
        users = cls.get_users()
        for user in users:
            if user.email.lower() == email.lower():
                return user
        return None

    @classmethod
    def create_user(cls, username, email, password, role='user'):
        users = cls.get_users()
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            password_hash=User.hash_password(password),
            role=role,
            is_banned=False
        )
        users.append(user)
        cls.save_users(users)
        return user

    @classmethod
    def update_user(cls, user_id, **kwargs):
        users = cls.get_users()
        for i, user in enumerate(users):
            if user.id == user_id:
                if 'role' in kwargs:
                    user.role = kwargs['role']
                if 'is_banned' in kwargs:
                    user.is_banned = kwargs['is_banned']
                if 'email' in kwargs:
                    user.email = kwargs['email']
                users[i] = user
                cls.save_users(users)
                return user
        return None

    @classmethod
    def get_reports_for_user(cls, user_id):
        reports = cls.get_reports()
        return [r for r in reports if r.get('user_id') == user_id]

    @classmethod
    def get_app_rating_from_reports(cls, app_id):
        """Calculate average rating from community reports."""
        reports = cls.get_reports_for_app(app_id)
        if not reports:
            return 0, 0  # rating, count

        ratings = [r.get('rating', 0) for r in reports if r.get('rating', 0) > 0]
        if not ratings:
            return 0, len(reports)

        avg = sum(ratings) / len(ratings)
        return round(avg, 1), len(reports)

    @classmethod
    def get_app_status_from_reports(cls, app_id):
        """Determine android support status from community reports (legacy)."""
        reports = cls.get_reports_for_app(app_id)
        if not reports:
            return None

        # Count statuses
        status_counts = {'yes': 0, 'partial': 0, 'no': 0, 'unknown': 0}
        for r in reports:
            # Support both old and new field names
            status = r.get('works') or r.get('android_support_works', 'unknown')
            if status in status_counts:
                status_counts[status] += 1

        # Return the most common status (excluding unknown)
        known_statuses = {k: v for k, v in status_counts.items() if k != 'unknown' and v > 0}
        if not known_statuses:
            return None

        return max(known_statuses, key=known_statuses.get)

    @classmethod
    def get_app_ratings_by_platform(cls, app_id):
        """
        Calculate compatibility ratings from community reports grouped by platform.
        Returns dict with 'android', 'native', 'browser' keys, each containing:
        - status: 'yes', 'partial', 'no', or None
        - count: number of reports
        - works_count: breakdown of yes/partial/no counts
        """
        reports = cls.get_reports_for_app(app_id)

        result = {
            'android': {'status': None, 'count': 0, 'works_count': {'yes': 0, 'partial': 0, 'no': 0}},
            'native': {'status': None, 'count': 0, 'works_count': {'yes': 0, 'partial': 0, 'no': 0}},
            'browser': {'status': None, 'count': 0, 'works_count': {'yes': 0, 'partial': 0, 'no': 0}},
        }

        if not reports:
            return result

        for r in reports:
            platform = r.get('platform')
            # Handle legacy reports without platform field
            if not platform:
                # Old reports were for Android support
                if r.get('android_support_works'):
                    platform = 'android'
                elif r.get('browser_works'):
                    platform = 'browser'
                else:
                    continue

            if platform not in result:
                continue

            # Get works status (support both old and new field names)
            works = r.get('works') or r.get('android_support_works') or r.get('browser_works')
            if works in ['yes', 'partial', 'no']:
                result[platform]['count'] += 1
                result[platform]['works_count'][works] += 1

        # Calculate the overall status for each platform (most common response)
        for platform in result:
            counts = result[platform]['works_count']
            total = result[platform]['count']
            if total > 0:
                # Find the most common status
                max_status = max(counts, key=counts.get)
                if counts[max_status] > 0:
                    result[platform]['status'] = max_status

        return result

    @classmethod
    def delete_user(cls, user_id):
        users = cls.get_users()
        users = [u for u in users if u.id != user_id]
        cls.save_users(users)
        return True

    # Reports management
    @classmethod
    def get_reports(cls):
        data = cls._load_json(current_app.config['REPORTS_JSON'])
        return data.get('reports', [])

    @classmethod
    def get_reports_for_app(cls, app_id):
        reports = cls.get_reports()
        return [r for r in reports if r.get('app_id') == app_id]

    @classmethod
    def save_reports(cls, reports):
        cls._save_json(current_app.config['REPORTS_JSON'], {'reports': reports})

    @classmethod
    def add_report(cls, report_data):
        reports = cls.get_reports()
        report_data['id'] = str(uuid.uuid4())
        report_data['created_at'] = datetime.utcnow().isoformat()
        reports.append(report_data)
        cls.save_reports(reports)

        # Update app reports count
        app_id = report_data.get('app_id')
        if app_id:
            cls._increment_app_reports_count(app_id)

        return report_data

    @classmethod
    def _increment_app_reports_count(cls, app_id):
        apps = cls.get_apps()
        for i, app in enumerate(apps):
            if app['id'] == app_id:
                apps[i]['reports_count'] = app.get('reports_count', 0) + 1
                apps[i]['updated_at'] = datetime.utcnow().isoformat()
                cls.save_apps(apps)
                break

    @classmethod
    def _decrement_app_reports_count(cls, app_id):
        apps = cls.get_apps()
        for i, app in enumerate(apps):
            if app['id'] == app_id:
                current_count = app.get('reports_count', 0)
                apps[i]['reports_count'] = max(0, current_count - 1)
                apps[i]['updated_at'] = datetime.utcnow().isoformat()
                cls.save_apps(apps)
                break

    @classmethod
    def delete_report(cls, report_id):
        reports = cls.get_reports()
        report = next((r for r in reports if r.get('id') == report_id), None)
        if not report:
            return False

        reports = [r for r in reports if r.get('id') != report_id]
        cls.save_reports(reports)

        app_id = report.get('app_id')
        if app_id:
            cls._decrement_app_reports_count(app_id)

        return True
