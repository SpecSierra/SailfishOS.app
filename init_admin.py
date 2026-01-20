#!/usr/bin/env python3
"""Initialize admin user with proper password hash."""

import json
import os
from argon2 import PasswordHasher

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
USERS_JSON = os.path.join(DATA_DIR, 'users.json')

ph = PasswordHasher()

def create_admin(username='admin', password='admin123', email='admin@sailfishos.app'):
    """Create or update admin user."""
    password_hash = ph.hash(password)

    users_data = {
        'users': [
            {
                'id': '1',
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'role': 'admin'
            }
        ]
    }

    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_JSON, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=2)

    print(f"Admin user created successfully!")
    print(f"  Username: {username}")
    print(f"  Password: {password}")
    print(f"  Email: {email}")


if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3:
        create_admin(sys.argv[1], sys.argv[2])
    else:
        create_admin()
