#!/usr/bin/env python3
"""
Migration script for V3 permission system.

This script:
1. Ensures all users have a 'role' field (defaults to 'user')
2. Ensures all users have an 'is_banned' field (defaults to False)
3. Initializes empty logs.json if it doesn't exist
"""
import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
USERS_JSON = os.path.join(DATA_DIR, 'users.json')
LOGS_JSON = os.path.join(DATA_DIR, 'logs.json')


def migrate_users():
    """Ensure all users have role and is_banned fields."""
    if not os.path.exists(USERS_JSON):
        print(f'Users file not found: {USERS_JSON}')
        return

    with open(USERS_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    users = data.get('users', [])
    updated = 0

    for user in users:
        if 'role' not in user:
            user['role'] = 'user'
            updated += 1
            print(f"  Added role='user' to user: {user.get('username')}")

        if 'is_banned' not in user:
            user['is_banned'] = False
            updated += 1
            print(f"  Added is_banned=False to user: {user.get('username')}")

    if updated:
        with open(USERS_JSON, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f'Updated {updated} user fields.')
    else:
        print('All users already have required fields.')


def init_logs():
    """Initialize empty logs.json if it doesn't exist."""
    if os.path.exists(LOGS_JSON):
        print(f'Logs file already exists: {LOGS_JSON}')
        return

    with open(LOGS_JSON, 'w', encoding='utf-8') as f:
        json.dump({'logs': []}, f, indent=2)
    print(f'Created empty logs file: {LOGS_JSON}')


def main():
    print('=' * 50)
    print('Sailfishos.app V3 Migration')
    print('=' * 50)

    print('\n1. Migrating users...')
    migrate_users()

    print('\n2. Initializing logs...')
    init_logs()

    print('\n' + '=' * 50)
    print('Migration completed successfully!')
    print('=' * 50)


if __name__ == '__main__':
    main()
