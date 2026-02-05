"""
Flask-WTF forms for the web interface.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo
from wtforms.widgets import PasswordInput
import re

from utils.validators import PasswordValidator
from security.constants import MIN_PASSWORD_LENGTH


class EncryptionForm(FlaskForm):
    """Form for file encryption."""
    
    file = FileField(
        'File to Encrypt',
        validators=[
            FileRequired(message="Please select a file"),
            FileAllowed(['txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'zip'], 
                       message='File type not allowed')
        ],
        description="Select file to encrypt"
    )
    
    password = PasswordField(
        'Encryption Password',
        validators=[
            DataRequired(message="Password is required"),
            Length(min=MIN_PASSWORD_LENGTH, 
                  message=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        ],
        widget=PasswordInput(hide_value=False),
        description="Enter strong password for encryption"
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message="Please confirm password"),
            EqualTo('password', message="Passwords must match")
        ],
        widget=PasswordInput(hide_value=False),
        description="Re-enter password"
    )
    
    delete_original = BooleanField(
        'Delete Original After Encryption',
        default=False,
        description="Securely delete original file after encryption"
    )
    
    def validate_password(self, field):
        """Custom password validation."""
        try:
            PasswordValidator.validate(field.data)
        except Exception as e:
            raise ValidationError(str(e))
    
    def validate_file(self, field):
        """Custom file validation."""
        if field.data:
            filename = field.data.filename
            # Basic filename sanitization
            if not re.match(r'^[\w\-. ]+$', filename):
                raise ValidationError('Invalid filename')
            if len(filename) > 255:
                raise ValidationError('Filename too long')


class DecryptionForm(FlaskForm):
    """Form for file decryption."""
    
    file = FileField(
        'Encrypted File',
        validators=[
            FileRequired(message="Please select a file"),
            FileAllowed(['enc'], message='Only .enc files are allowed')
        ],
        description="Select encrypted file (.enc)"
    )
    
    password = PasswordField(
        'Decryption Password',
        validators=[
            DataRequired(message="Password is required")
        ],
        widget=PasswordInput(hide_value=False),
        description="Enter password used for encryption"
    )


class SecuritySettingsForm(FlaskForm):
    """Form for security settings."""
    
    encryption_algorithm = SelectField(
        'Encryption Algorithm',
        choices=[
            ('aes-256-gcm', 'AES-256-GCM (Recommended)'),
            ('aes-256-cbc', 'AES-256-CBC'),
            ('chacha20', 'ChaCha20-Poly1305')
        ],
        default='aes-256-gcm',
        description="Select encryption algorithm"
    )
    
    key_derivation = SelectField(
        'Key Derivation Function',
        choices=[
            ('argon2id', 'Argon2id (Memory-hard, recommended)'),
            ('pbkdf2', 'PBKDF2 (Compatibility mode)')
        ],
        default='argon2id',
        description="Select key derivation function"
    )
    
    session_timeout = SelectField(
        'Session Timeout',
        choices=[
            ('300', '5 minutes'),
            ('900', '15 minutes'),
            ('1800', '30 minutes'),
            ('3600', '1 hour')
        ],
        default='1800',
        description="Automatic logout after inactivity"
    )
    
    require_2fa = BooleanField(
        'Require Two-Factor Authentication',
        default=False,
        description="Enable 2FA for additional security"
    )


class PasswordStrengthForm(FlaskForm):
    """Form for password strength checking."""
    
    password = StringField(
        'Password to Check',
        validators=[DataRequired()],
        description="Enter password to check strength"
    )
    
    def validate_password(self, field):
        """Check password strength."""
        strength = PasswordValidator.estimate_strength(field.data)
        self.strength_score = strength
        
        if strength < 0.3:
            raise ValidationError('Very weak password')
        elif strength < 0.5:
            raise ValidationError('Weak password')
        elif strength < 0.7:
            raise ValidationError('Moderate password')
        else:
            # Good password
            pass