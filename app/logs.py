"""
Audit logging system for tracking user actions with rollback support.
"""
import json
import os
import uuid
from datetime import datetime
from flask import current_app


class LogManager:
    """Manages audit logs for the application."""

    # Action types
    ACTION_APP_ADDED = 'app_added'
    ACTION_APP_EDITED = 'app_edited'
    ACTION_APP_DELETED = 'app_deleted'
    ACTION_REPORT_ADDED = 'report_added'
    ACTION_REPORT_DELETED = 'report_deleted'
    ACTION_USER_CREATED = 'user_created'
    ACTION_USER_ROLE_CHANGED = 'user_role_changed'
    ACTION_USER_BANNED = 'user_banned'
    ACTION_USER_UNBANNED = 'user_unbanned'
    ACTION_CATEGORY_ADDED = 'category_added'
    ACTION_CATEGORY_EDITED = 'category_edited'
    ACTION_CATEGORY_DELETED = 'category_deleted'
    ACTION_ROLLBACK = 'rollback'

    @staticmethod
    def _load_logs():
        """Load logs from JSON file."""
        filepath = current_app.config.get('LOGS_JSON')
        if filepath and os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('logs', [])
        return []

    @staticmethod
    def _save_logs(logs):
        """Save logs to JSON file."""
        filepath = current_app.config.get('LOGS_JSON')
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({'logs': logs}, f, indent=2, ensure_ascii=False)

    @classmethod
    def log_action(cls, user_id, username, action, entity_type, entity_id=None,
                   old_data=None, new_data=None, description=None):
        """
        Record an action to the audit log.

        Args:
            user_id: ID of the user performing the action
            username: Username of the user performing the action
            action: Type of action (use ACTION_* constants)
            entity_type: Type of entity affected (app, report, user, category)
            entity_id: ID of the affected entity (optional)
            old_data: Previous state of the entity (for edits/deletes)
            new_data: New state of the entity (for adds/edits)
            description: Optional human-readable description

        Returns:
            The created log entry
        """
        log_entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'username': username,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'old_data': old_data,
            'new_data': new_data,
            'description': description,
            'rolled_back': False,
            'rolled_back_by': None,
            'rolled_back_at': None
        }

        logs = cls._load_logs()
        logs.insert(0, log_entry)  # Insert at beginning (newest first)
        cls._save_logs(logs)

        return log_entry

    @classmethod
    def get_logs(cls, limit=100, offset=0, action_filter=None,
                 entity_type_filter=None, user_id_filter=None):
        """
        Get logs with optional filtering.

        Args:
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            action_filter: Filter by action type
            entity_type_filter: Filter by entity type
            user_id_filter: Filter by user ID

        Returns:
            List of log entries
        """
        logs = cls._load_logs()

        # Apply filters
        if action_filter:
            logs = [l for l in logs if l.get('action') == action_filter]
        if entity_type_filter:
            logs = [l for l in logs if l.get('entity_type') == entity_type_filter]
        if user_id_filter:
            logs = [l for l in logs if l.get('user_id') == user_id_filter]

        # Apply pagination
        total = len(logs)
        logs = logs[offset:offset + limit]

        return logs, total

    @classmethod
    def get_log_by_id(cls, log_id):
        """Get a specific log entry by ID."""
        logs = cls._load_logs()
        for log in logs:
            if log.get('id') == log_id:
                return log
        return None

    @classmethod
    def mark_as_rolled_back(cls, log_id, rolled_back_by_user_id, rolled_back_by_username):
        """Mark a log entry as rolled back."""
        logs = cls._load_logs()
        for log in logs:
            if log.get('id') == log_id:
                log['rolled_back'] = True
                log['rolled_back_by'] = rolled_back_by_user_id
                log['rolled_back_by_username'] = rolled_back_by_username
                log['rolled_back_at'] = datetime.utcnow().isoformat()
                cls._save_logs(logs)
                return True
        return False

    @classmethod
    def get_action_display_name(cls, action):
        """Get human-readable name for an action."""
        display_names = {
            cls.ACTION_APP_ADDED: 'App Added',
            cls.ACTION_APP_EDITED: 'App Edited',
            cls.ACTION_APP_DELETED: 'App Deleted',
            cls.ACTION_REPORT_ADDED: 'Report Added',
            cls.ACTION_REPORT_DELETED: 'Report Deleted',
            cls.ACTION_USER_CREATED: 'User Created',
            cls.ACTION_USER_ROLE_CHANGED: 'User Role Changed',
            cls.ACTION_USER_BANNED: 'User Banned',
            cls.ACTION_USER_UNBANNED: 'User Unbanned',
            cls.ACTION_CATEGORY_ADDED: 'Category Added',
            cls.ACTION_CATEGORY_EDITED: 'Category Edited',
            cls.ACTION_CATEGORY_DELETED: 'Category Deleted',
            cls.ACTION_ROLLBACK: 'Rollback',
        }
        return display_names.get(action, action)

    @classmethod
    def get_entity_type_icon(cls, entity_type):
        """Get FontAwesome icon for entity type."""
        icons = {
            'app': 'fa-mobile-alt',
            'report': 'fa-clipboard-list',
            'user': 'fa-user',
            'category': 'fa-tags',
        }
        return icons.get(entity_type, 'fa-question')
