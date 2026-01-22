from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, BooleanField, IntegerField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange, EqualTo, ValidationError


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
    android_name = StringField('Android App Name', validators=[DataRequired(), Length(max=100)])
    android_package = StringField('Package Name', validators=[Optional(), Length(max=150)])
    android_description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    android_icon_url = StringField('Icon URL', validators=[Optional(), Length(max=500)])

    category = SelectField('Category', validators=[DataRequired()])

    # Country/region (multi-select)
    countries = SelectMultipleField('Countries/Regions', choices=COUNTRIES[1:], validators=[Optional()])

    # Multiple native apps support (JSON text area for flexibility)
    native_exists = BooleanField('Native App Exists')
    native_name = StringField('Native App Name', validators=[Optional(), Length(max=100)])
    native_store_url = StringField('Store URL', validators=[Optional(), Length(max=500)])
    native_rating = SelectField('Native App Rating', choices=[
        ('none', 'Not Rated'),
        ('platinum', 'Platinum - Feature complete'),
        ('gold', 'Gold - Most features work'),
        ('silver', 'Silver - Core features work'),
        ('bronze', 'Bronze - Limited functionality'),
    ], default='none')
    # Additional native apps (JSON format for multiple entries)
    additional_native_apps = TextAreaField('Additional Native Apps (JSON)', validators=[Optional(), Length(max=2000)])


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
        Length(min=8, message='Password must be at least 8 characters')
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
