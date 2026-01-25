import os
import warnings
from dotenv import load_dotenv

load_dotenv()


# Test keys for hCaptcha (used in development only)
HCAPTCHA_TEST_SITE_KEY = '10000000-ffff-ffff-ffff-000000000001'
HCAPTCHA_TEST_SECRET_KEY = '0x0000000000000000000000000000000000000000'


class Config:
    # Development mode flag
    DEV_MODE = os.environ.get('DEV_MODE', 'false').lower() == 'true'
    DEBUG = DEV_MODE

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    APP_VERSION = os.environ.get('APP_VERSION') or '0.0.1'
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    APPS_JSON = os.path.join(DATA_DIR, 'apps.json')
    USERS_JSON = os.path.join(DATA_DIR, 'users.json')
    CATEGORIES_JSON = os.path.join(DATA_DIR, 'categories.json')
    REPORTS_JSON = os.path.join(DATA_DIR, 'reports.json')
    LOGS_JSON = os.path.join(DATA_DIR, 'logs.json')
    ICONS_DIR = os.path.join(DATA_DIR, 'icons')

    # hCaptcha configuration
    # Get your keys from https://www.hcaptcha.com/
    HCAPTCHA_SITE_KEY = os.environ.get('HCAPTCHA_SITE_KEY') or HCAPTCHA_TEST_SITE_KEY
    HCAPTCHA_SECRET_KEY = os.environ.get('HCAPTCHA_SECRET_KEY') or HCAPTCHA_TEST_SECRET_KEY
    HCAPTCHA_VERIFY_URL = 'https://hcaptcha.com/siteverify'

    # Warn if using test keys in non-development mode
    if not DEV_MODE:
        if HCAPTCHA_SITE_KEY == HCAPTCHA_TEST_SITE_KEY:
            warnings.warn(
                'SECURITY WARNING: Using test hCaptcha keys in non-development mode. '
                'Set HCAPTCHA_SITE_KEY and HCAPTCHA_SECRET_KEY environment variables for production.',
                UserWarning
            )
        if SECRET_KEY == 'dev-secret-key-change-in-production':
            warnings.warn(
                'SECURITY WARNING: Using default SECRET_KEY in non-development mode. '
                'Set SECRET_KEY environment variable for production.',
                UserWarning
            )
