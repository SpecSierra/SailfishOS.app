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
        ('0', 'Not Rated'),
        ('1', '1 - Poor'),
        ('2', '2 - Fair'),
        ('3', '3 - Good'),
        ('4', '4 - Very Good'),
        ('5', '5 - Excellent')
    ], default='0')
    # Additional native apps (JSON format for multiple entries)
    additional_native_apps = TextAreaField('Additional Native Apps (JSON)', validators=[Optional(), Length(max=2000)])

    android_support_works = SelectField('Android App Support', choices=[
        ('unknown', 'Unknown'),
        ('yes', 'Works'),
        ('partial', 'Partial'),
        ('no', 'Does Not Work')
    ], default='unknown')
    android_support_rating = SelectField('Android Support Rating', choices=[
        ('0', 'Not Rated'),
        ('1', '1 - Poor'),
        ('2', '2 - Fair'),
        ('3', '3 - Good'),
        ('4', '4 - Very Good'),
        ('5', '5 - Excellent')
    ], default='0')
    android_support_notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])

    # microG/GApps dependency
    dependency = SelectField('Google Services Dependency', choices=DEPENDENCY_CHOICES, default='none')

    # Browser compatibility
    browser_works = SelectField('Works in SailfishOS Browser', choices=[
        ('unknown', 'Unknown'),
        ('yes', 'Yes, works in browser'),
        ('partial', 'Partially works'),
        ('no', 'Does not work in browser'),
        ('na', 'Not applicable (no web version)')
    ], default='unknown')
    browser_notes = TextAreaField('Browser Notes', validators=[Optional(), Length(max=500)])


class SearchForm(FlaskForm):
    q = StringField('Search', validators=[Optional(), Length(max=100)])
    category = SelectField('Category', choices=[('', 'All Categories')], default='')
    status = SelectField('Status', choices=[
        ('', 'All Status'),
        ('native', 'Has Native App'),
        ('works', 'Android Support Works'),
        ('partial', 'Partial Support'),
        ('no', 'Does Not Work'),
        ('unknown', 'Unknown'),
        ('browser', 'Works in Browser'),
        ('microg', 'Requires microG'),
        ('gapps', 'Requires GApps'),
    ], default='')
    country = SelectField('Country/Region', choices=COUNTRIES, default='')


class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(max=50)])
    slug = StringField('Slug', validators=[DataRequired(), Length(max=50)])
    icon = StringField('FontAwesome Icon', validators=[Optional(), Length(max=50)])


class ReportForm(FlaskForm):
    """User report form for app compatibility (no account required)."""
    reporter_name = StringField('Your Name', validators=[Optional(), Length(max=50)])

    android_support_works = SelectField('Does it work via Android App Support?', choices=[
        ('', '-- Select --'),
        ('yes', 'Yes, it works'),
        ('partial', 'Partially works'),
        ('no', 'Does not work'),
        ('unknown', 'I don\'t know')
    ], validators=[DataRequired(message='Please select a compatibility status')])

    rating = SelectField('Overall Rating', choices=[
        ('', '-- Select --'),
        ('1', '1 - Unusable'),
        ('2', '2 - Poor'),
        ('3', '3 - Usable'),
        ('4', '4 - Good'),
        ('5', '5 - Perfect')
    ], validators=[DataRequired(message='Please select a rating')])

    # microG/GApps dependency
    dependency = SelectField('Google Services Required?', choices=[
        ('', '-- Select --'),
        ('none', 'No - works without Google Services'),
        ('microg', 'Requires microG'),
        ('gapps', 'Requires Open GApps'),
        ('microg_or_gapps', 'Requires microG or GApps'),
    ], validators=[Optional()])

    # Browser compatibility
    browser_works = SelectField('Works in SailfishOS Browser?', choices=[
        ('', '-- Select --'),
        ('yes', 'Yes, web version works'),
        ('partial', 'Partially works in browser'),
        ('no', 'Does not work in browser'),
        ('na', 'Not applicable / No web version'),
    ], validators=[Optional()])

    device = StringField('Device Model', validators=[Optional(), Length(max=100)])
    sailfish_version = StringField('SailfishOS Version', validators=[Optional(), Length(max=50)])
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
