import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    APP_VERSION = os.environ.get('APP_VERSION') or '0.0.1'
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    APPS_JSON = os.path.join(DATA_DIR, 'apps.json')
    USERS_JSON = os.path.join(DATA_DIR, 'users.json')
    CATEGORIES_JSON = os.path.join(DATA_DIR, 'categories.json')
    REPORTS_JSON = os.path.join(DATA_DIR, 'reports.json')

    # hCaptcha configuration
    # Get your keys from https://www.hcaptcha.com/
    HCAPTCHA_SITE_KEY = os.environ.get('HCAPTCHA_SITE_KEY') or '10000000-ffff-ffff-ffff-000000000001'  # Test key
    HCAPTCHA_SECRET_KEY = os.environ.get('HCAPTCHA_SECRET_KEY') or '0x0000000000000000000000000000000000000000'  # Test key
    HCAPTCHA_VERIFY_URL = 'https://hcaptcha.com/siteverify'
