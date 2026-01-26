import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, BooleanField, IntegerField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange, EqualTo, ValidationError


def validate_password_complexity(form, field):
    """Validate password meets complexity requirements."""
    password = field.data
    errors = []

    if not re.search(r'[A-Z]', password):
        errors.append('one uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('one lowercase letter')
    if not re.search(r'\d', password):
        errors.append('one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('one special character (!@#$%^&*(),.?":{}|<>)')

    if errors:
        raise ValidationError(f'Password must contain at least: {", ".join(errors)}')


def validate_package_name(form, field):
    """Validate Android package name format."""
    if not field.data:
        return  # Optional field

    package = field.data.strip()

    # Check basic format: must have at least one dot
    if '.' not in package:
        raise ValidationError('Package name must be in format: com.example.app')

    # Check for valid characters (letters, numbers, dots, underscores)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_.]*[a-zA-Z0-9]$', package):
        raise ValidationError('Package name contains invalid characters')

    # Check for path traversal attempts
    if '..' in package or '/' in package or '\\' in package:
        raise ValidationError('Invalid package name format')

    # Check each segment
    segments = package.split('.')
    if len(segments) < 2:
        raise ValidationError('Package name must have at least 2 segments (e.g., com.example)')

    for segment in segments:
        if not segment:
            raise ValidationError('Package name cannot have empty segments')
        if segment[0].isdigit():
            raise ValidationError('Package name segments cannot start with a number')


def validate_url(form, field):
    """Validate URL format (if provided)."""
    if not field.data:
        return  # Optional field

    url = field.data.strip()

    # Allow relative paths starting with /
    if url.startswith('/'):
        # Validate relative path format (no directory traversal, valid characters)
        relative_pattern = re.compile(r'^/[a-zA-Z0-9/_.-]+$')
        if not relative_pattern.match(url):
            raise ValidationError('Invalid relative path format')
        if '..' in url:
            raise ValidationError('Directory traversal not allowed')
        return

    # Basic URL pattern check for absolute URLs
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not url_pattern.match(url):
        raise ValidationError('Please enter a valid URL (must start with http://, https://, or /)')


# Country list for filtering (countries where Jolla phones are sold + common regions)
COUNTRIES = [
    ('', 'All Countries'),
    ('FI', 'Finland'),
    ('NO', 'Norway'),
    ('SE', 'Sweden'),
    ('DE', 'Germany'),
    ('FR', 'France'),
    ('IT', 'Italy'),
    ('ES', 'Spain'),
    ('UK', 'United Kingdom'),
    ('US', 'United States'),
    ('RU', 'Russia'),
    ('IN', 'India'),
    ('CN', 'China'),
    ('JP', 'Japan'),
    ('AU', 'Australia'),
    ('NL', 'Netherlands'),
    ('PL', 'Poland'),
    ('CH', 'Switzerland'),
    ('AT', 'Austria'),
    ('BE', 'Belgium'),
    ('DK', 'Denmark'),
    ('PT', 'Portugal'),
    ('CZ', 'Czech Republic'),
    ('HU', 'Hungary'),
    ('GLOBAL', 'Global / Worldwide'),
]

# Dependency options for microG/GApps
DEPENDENCY_CHOICES = [
    ('none', 'No special requirements'),
    ('microg', 'Requires microG'),
    ('gapps', 'Requires Open GApps'),
    ('microg_or_gapps', 'Requires microG or GApps'),
]

# Official SailfishOS supported devices
SUPPORTED_DEVICES = [
    ('', '-- Select Device --'),
    # Currently supported devices
    ('Jolla C2', 'Jolla C2'),
    ('Xperia 10 V', 'Xperia 10 V'),
    ('Xperia 10 IV', 'Xperia 10 IV'),
    ('Xperia 10 III', 'Xperia 10 III'),
    ('Xperia 10 II', 'Xperia 10 II'),
    ('Xperia 10', 'Xperia 10'),
    ('Xperia 10 Plus', 'Xperia 10 Plus'),
    ('Xperia XA2', 'Xperia XA2'),
    ('Xperia XA2 Plus', 'Xperia XA2 Plus'),
    ('Xperia XA2 Ultra', 'Xperia XA2 Ultra'),
    # Ceased support devices
    ('Gemini PDA', 'Gemini PDA [Legacy]'),
    ('Xperia X', 'Xperia X [Legacy]'),
    ('Jolla C', 'Jolla C [Legacy]'),
    ('Jolla Tablet', 'Jolla Tablet [Legacy]'),
    ('Jolla Phone', 'Jolla Phone [Legacy]'),
    # Custom option
    ('custom', 'Other (Custom Device)'),
]

# SailfishOS versions
SFOS_VERSIONS = [
    ('', '-- Select Version --'),
    ('5.0', '5.0'),
    ('4.6', '4.6'),
    ('4.5', '4.5'),
    ('4.4', '4.4'),
    ('4.3', '4.3'),
    ('4.2', '4.2'),
    ('4.1', '4.1'),
    ('4.0', '4.0'),
    ('3.4', '3.4'),
    ('3.3', '3.3'),
    ('3.2', '3.2'),
    ('3.1', '3.1'),
    ('3.0', '3.0'),
    ('custom', 'Other (Custom Version)'),
]


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')


class AppForm(FlaskForm):
    android_name = StringField('Android App Name', validators=[
        DataRequired(message='App name is required'),
        Length(min=1, max=100, message='App name must be between 1 and 100 characters')
    ])
    android_package = StringField('Package Name', validators=[
        Optional(),
        Length(max=150, message='Package name cannot exceed 150 characters'),
        validate_package_name
    ])
    android_description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=500, message='Description cannot exceed 500 characters')
    ])
    android_icon_url = StringField('Icon URL', validators=[
        Optional(),
        Length(max=500, message='URL cannot exceed 500 characters'),
        validate_url
    ])

    category = SelectField('Category', validators=[DataRequired(message='Please select a category')])

    # Country/region (multi-select)
    countries = SelectMultipleField('Countries/Regions', choices=COUNTRIES[1:], validators=[Optional()])

    # Multiple native apps support (JSON text area for flexibility)
    native_exists = BooleanField('Native App Exists')
    native_name = StringField('Native App Name', validators=[
        Optional(),
        Length(max=100, message='Native app name cannot exceed 100 characters')
    ])
    native_store_url = StringField('Store URL', validators=[
        Optional(),
        Length(max=500, message='URL cannot exceed 500 characters'),
        validate_url
    ])
    native_rating = SelectField('Native App Rating', choices=[
        ('none', 'Not Rated'),
        ('platinum', 'Platinum - Feature complete'),
        ('gold', 'Gold - Most features work'),
        ('silver', 'Silver - Core features work'),
        ('bronze', 'Bronze - Limited functionality'),
    ], default='none')
    # Additional native apps (JSON format for multiple entries)
    additional_native_apps = TextAreaField('Additional Native Apps (JSON)', validators=[
        Optional(),
        Length(max=2000, message='Additional apps JSON cannot exceed 2000 characters')
    ])


class SearchForm(FlaskForm):
    q = StringField('Search', validators=[Optional(), Length(max=100)])
    category = SelectField('Category', choices=[('', 'All Categories')], default='')
    status = SelectField('Status', choices=[
        ('', 'All Status'),
        ('native', 'Has Native App'),
    ], default='')
    country = SelectField('Country/Region', choices=COUNTRIES, default='')


class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(max=50)])
    slug = StringField('Slug', validators=[DataRequired(), Length(max=50)])
    icon = StringField('FontAwesome Icon', validators=[Optional(), Length(max=50)])


class ReportForm(FlaskForm):
    """User report form for app compatibility (no account required)."""
    reporter_name = StringField('Your Name', validators=[Optional(), Length(max=50)])

    # Platform being tested
    platform = SelectField('What are you testing?', choices=[
        ('', '-- Select Platform --'),
        ('android', 'Android App (via Android App Support)'),
        ('native', 'Native SailfishOS App'),
        ('browser', 'Web Browser'),
    ], validators=[DataRequired(message='Please select which platform you are testing')])

    native_app = SelectField('Native App', choices=[
        ('', '-- Select native app --')
    ], validators=[Optional()])
    custom_native_app = StringField('Custom Native App', validators=[Optional(), Length(max=100)])

    # Does it work?
    works = SelectField('Does it work?', choices=[
        ('', '-- Select --'),
        ('yes', 'Yes, it works'),
        ('partial', 'Partially works'),
        ('no', 'Does not work'),
    ], validators=[DataRequired(message='Please select a compatibility status')])

    # Google Services dependency (only for Android platform)
    dependency = SelectField('Google Services Required?', choices=[
        ('', '-- Select --'),
        ('none', 'No - works without Google Services'),
        ('microg', 'Requires microG'),
        ('gapps', 'Requires Open GApps'),
        ('microg_or_gapps', 'Requires microG or GApps'),
    ], validators=[Optional()])

    device = SelectField('Device Model', choices=SUPPORTED_DEVICES, validators=[Optional()])
    custom_device = StringField('Custom Device', validators=[Optional(), Length(max=100)])
    sailfish_version = SelectField('SailfishOS Version', choices=SFOS_VERSIONS, validators=[Optional()])
    custom_sailfish_version = StringField('Custom SFOS Version', validators=[Optional(), Length(max=50)])
    app_version = StringField('App Version', validators=[Optional(), Length(max=50)])

    notes = TextAreaField('Notes / Details', validators=[Optional(), Length(max=2000)])


class RegistrationForm(FlaskForm):
    """User registration form."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50, message='Username must be between 3 and 50 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters'),
        validate_password_complexity
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])


class AppSubmitForm(FlaskForm):
    """Form for users to submit a new app by package name."""
    android_package = StringField('Play Store Package Name', validators=[
        DataRequired(),
        Length(min=3, max=150, message='Package name must be between 3 and 150 characters')
    ])
    category = SelectField('Category', validators=[DataRequired()])

    def validate_android_package(self, field):
        # Basic package name validation
        package = field.data.strip()
        if not package:
            raise ValidationError('Package name is required')
        # Package names typically have format: com.example.app
        if '.' not in package:
            raise ValidationError('Invalid package name format. Example: com.whatsapp')


class TwoFactorSetupForm(FlaskForm):
    """Form for verifying TOTP code during 2FA setup."""
    totp_code = StringField('Verification Code', validators=[
        DataRequired(message='Please enter the 6-digit code from your authenticator app'),
        Length(min=6, max=6, message='Code must be exactly 6 digits')
    ])

    def validate_totp_code(self, field):
        code = field.data.replace(' ', '').replace('-', '')
        if not code.isdigit():
            raise ValidationError('Code must contain only digits')


class TwoFactorVerifyForm(FlaskForm):
    """Form for verifying TOTP code during login."""
    totp_code = StringField('Authentication Code', validators=[
        DataRequired(message='Please enter the 6-digit code from your authenticator app'),
        Length(min=6, max=6, message='Code must be exactly 6 digits')
    ])

    def validate_totp_code(self, field):
        code = field.data.replace(' ', '').replace('-', '')
        if not code.isdigit():
            raise ValidationError('Code must contain only digits')


class TwoFactorDisableForm(FlaskForm):
    """Form for disabling 2FA (requires password confirmation)."""
    password = PasswordField('Current Password', validators=[
        DataRequired(message='Please enter your password to disable 2FA')
    ])
    totp_code = StringField('Authentication Code', validators=[
        DataRequired(message='Please enter the 6-digit code from your authenticator app'),
        Length(min=6, max=6, message='Code must be exactly 6 digits')
    ])


class PasswordChangeForm(FlaskForm):
    """Form for changing password (for logged-in users)."""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Please enter your current password')
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='Please enter a new password'),
        Length(min=8, message='Password must be at least 8 characters'),
        validate_password_complexity
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your new password'),
        EqualTo('new_password', message='Passwords must match')
    ])
