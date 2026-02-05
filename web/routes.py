"""
Flask routes for web interface.
"""

import os
import secrets
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional

from flask import (
    Blueprint, render_template, request, jsonify,
    send_file, redirect, url_for, flash, session,
    current_app, abort, make_response
)
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from web.forms import EncryptionForm, DecryptionForm, SecuritySettingsForm, PasswordStrengthForm
from web.auth import SessionManager, RateLimiter, PasswordManager
from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_handler import FileHandler
from utils.validators import PasswordValidator, FileValidator
from security.exceptions import (
    AuthenticationError, DecryptionError, InvalidKeyError,
    PasswordTooWeakError, InvalidMetadataError
)
from utils.logger import logger

# ────────────────────────────────────────────────
# Blueprints
# ────────────────────────────────────────────────

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# ────────────────────────────────────────────────
# Global instances
# ────────────────────────────────────────────────

key_manager = KeyManager()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

# ────────────────────────────────────────────────
# Helper functions
# ────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    allowed_extensions = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'zip', 'enc'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def save_uploaded_file(file) -> Tuple[Optional[str], Optional[str]]:
    """
    Save uploaded file securely.
    
    Returns:
        Tuple[Optional[str], Optional[str]]: (filepath, error_message)
    """
    try:
        if file.filename == '':
            return None, "No file selected"
        
        if not allowed_file(file.filename):
            return None, "File type not allowed"
        
        filename = secure_filename(file.filename)
        random_prefix = secrets.token_hex(8)
        safe_filename = f"{random_prefix}_{filename}"
        
        upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        filepath = upload_dir / safe_filename
        file.save(str(filepath))
        
        try:
            os.chmod(filepath, 0o600)  # owner read/write only
        except:
            pass
        
        logger.info(f"File uploaded: {filename} -> {filepath}")
        return str(filepath), None
        
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        return None, str(e)


def cleanup_temp_file(filepath: str):
    """Securely delete temporary file."""
    try:
        if os.path.exists(filepath):
            if not FileHandler.secure_delete(filepath, passes=1):
                os.remove(filepath)
            logger.debug(f"Cleaned up temp file: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to cleanup {filepath}: {e}")


# ────────────────────────────────────────────────
# Before-request hook (main blueprint)
# ────────────────────────────────────────────────

@main_bp.before_request
def check_session():
    """Check session for protected routes."""
    protected_routes = ['/encrypt', '/decrypt', '/download', '/settings']
    
    if request.path in protected_routes:
        if not SessionManager.validate_session():
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('main.index'))


# ────────────────────────────────────────────────
# Main routes
# ────────────────────────────────────────────────

@main_bp.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@main_bp.route('/encrypt', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def encrypt():
    """File encryption page."""
    form = EncryptionForm()
    
    if form.validate_on_submit():
        try:
            ip = get_remote_address()
            if not RateLimiter.check_limit(f"encrypt_{ip}", 5, 300):
                flash('Too many encryption attempts. Please wait.', 'danger')
                return redirect(url_for('main.encrypt'))
            
            filepath, error = save_uploaded_file(form.file.data)
            if error:
                flash(f'Upload error: {error}', 'danger')
                return render_template('encrypt.html', form=form)
            
            try:
                is_valid, message = FileValidator.is_safe_to_encrypt(filepath)
                if not is_valid:
                    flash(f'File validation failed: {message}', 'danger')
                    cleanup_temp_file(filepath)
                    return render_template('encrypt.html', form=form)
                
                salt = key_manager.generate_salt()
                key = key_manager.derive_key(form.password.data, salt)
                
                plaintext = FileHandler.read_file(filepath)
                nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
                
                original_filename = secure_filename(form.file.data.filename)
                output_filename = f"{Path(original_filename).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
                
                from storage.metadata import FileMetadata
                metadata = FileMetadata.create_new(salt, nonce, tag)
                
                encrypted_filepath = str(Path(filepath).with_name(output_filename))
                FileHandler.write_encrypted_file(encrypted_filepath, metadata, ciphertext)
                
                if form.delete_original.data:
                    FileHandler.secure_delete(filepath)
                
                session['download_file'] = encrypted_filepath
                session['original_filename'] = Path(original_filename).stem + '.enc'
                session['file_size'] = len(ciphertext)
                
                # Zero sensitive memory
                key = b'\x00' * len(key)
                form.password.data = ' ' * len(form.password.data)
                
                flash('File encrypted successfully!', 'success')
                return redirect(url_for('main.download'))
                
            except (InvalidKeyError, PasswordTooWeakError) as e:
                flash(f'Encryption failed: {e}', 'danger')
                cleanup_temp_file(filepath)
                return render_template('encrypt.html', form=form)
                
            finally:
                if 'plaintext' in locals():
                    plaintext = b'\x00' * len(plaintext)
                if 'key' in locals():
                    key = b'\x00' * len(key)
        
        except Exception as e:
            logger.error(f"Encryption error: {e}", exc_info=True)
            flash('An unexpected error occurred during encryption.', 'danger')
            return render_template('encrypt.html', form=form)
    
    return render_template('encrypt.html', form=form)


@main_bp.route('/decrypt', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def decrypt():
    """File decryption page."""
    form = DecryptionForm()
    
    if form.validate_on_submit():
        try:
            ip = get_remote_address()
            if not RateLimiter.check_limit(f"decrypt_{ip}", 5, 300):
                flash('Too many decryption attempts. Please wait.', 'danger')
                return redirect(url_for('main.decrypt'))
            
            filepath, error = save_uploaded_file(form.file.data)
            if error:
                flash(f'Upload error: {error}', 'danger')
                return render_template('decrypt.html', form=form)
            
            try:
                metadata, ciphertext = FileHandler.read_encrypted_file(filepath)
                key = key_manager.derive_key(form.password.data, metadata.salt)
                plaintext = CryptoEngine.decrypt(key, metadata.nonce, ciphertext, metadata.tag)
                
                original_filename = secure_filename(form.file.data.filename)
                if original_filename.endswith('.enc'):
                    output_filename = original_filename[:-4] + '_decrypted'
                else:
                    output_filename = original_filename + '_decrypted'
                
                if plaintext[:4] == b'%PDF':
                    output_filename += '.pdf'
                elif plaintext[:2] == b'PK':
                    output_filename += '.zip'
                else:
                    output_filename += '.bin'
                
                decrypted_filepath = str(Path(filepath).with_name(output_filename))
                FileHandler.write_file_atomic(decrypted_filepath, plaintext, backup=False)
                
                session['download_file'] = decrypted_filepath
                session['original_filename'] = output_filename
                session['file_size'] = len(plaintext)
                
                cleanup_temp_file(filepath)
                key = b'\x00' * len(key)
                plaintext = b'\x00' * len(plaintext)
                form.password.data = ' ' * len(form.password.data)
                
                flash('File decrypted successfully!', 'success')
                return redirect(url_for('main.download'))
                
            except AuthenticationError as e:
                flash('❌ SECURITY ALERT: File may be tampered with or wrong password!', 'danger')
                logger.warning(f"Authentication failed for {filepath}")
                cleanup_temp_file(filepath)
                return render_template('decrypt.html', form=form)
                
            except (InvalidKeyError, DecryptionError, InvalidMetadataError) as e:
                flash(f'Decryption failed: {e}', 'danger')
                cleanup_temp_file(filepath)
                return render_template('decrypt.html', form=form)
                
            finally:
                if 'plaintext' in locals():
                    plaintext = b'\x00' * len(plaintext)
                if 'key' in locals():
                    key = b'\x00' * len(key)
        
        except Exception as e:
            logger.error(f"Decryption error: {e}", exc_info=True)
            flash('An unexpected error occurred during decryption.', 'danger')
            return render_template('decrypt.html', form=form)
    
    return render_template('decrypt.html', form=form)


@main_bp.route('/download')
def download():
    """Download encrypted/decrypted file."""
    if 'download_file' not in session or 'original_filename' not in session:
        flash('No file to download.', 'warning')
        return redirect(url_for('main.index'))
    
    filepath = session['download_file']
    original_filename = session['original_filename']
    
    if not os.path.exists(filepath):
        flash('File no longer exists.', 'danger')
        return redirect(url_for('main.index'))
    
    try:
        response = make_response(send_file(
            filepath,
            as_attachment=True,
            download_name=original_filename
        ))
        
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Disposition'] = f'attachment; filename="{original_filename}"'
        
        session.pop('download_file', None)
        session.pop('original_filename', None)
        session.pop('file_size', None)
        
        return response
        
    except Exception as e:
        logger.error(f"Download failed: {e}")
        flash('Download failed.', 'danger')
        return redirect(url_for('main.index'))


@main_bp.route('/security')
def security():
    """Security information page."""
    form = SecuritySettingsForm()
    return render_template('security.html', form=form)


@main_bp.route('/check-password', methods=['POST'])
def check_password():
    """Check password strength (AJAX endpoint)."""
    form = PasswordStrengthForm()
    
    if form.validate():
        strength = PasswordValidator.estimate_strength(form.password.data)
        estimate = key_manager.estimate_brute_force_time(form.password.data)
        
        return jsonify({
            'strength': strength,
            'estimate': estimate,
            'category': get_strength_category(strength),
            'suggestions': get_password_suggestions(form.password.data)
        })
    
    return jsonify({'error': 'Invalid input'}), 400


@main_bp.route('/clear-session')
def clear_session():
    """Clear current session."""
    SessionManager.destroy_session()
    flash('Session cleared.', 'info')
    return redirect(url_for('main.index'))


@main_bp.route('/results')
def results():
    """Show operation results."""
    operation = request.args.get('op', 'encrypt')
    context = {}
    
    if operation == 'encrypt':
        context.update({
            'original_filename': request.args.get('original', 'unknown'),
            'encrypted_filename': request.args.get('encrypted', 'unknown'),
            'original_size': request.args.get('original_size', '0'),
            'encrypted_size': request.args.get('encrypted_size', '0'),
            'timestamp': request.args.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'compression_ratio': request.args.get('ratio', '0'),
            'encryption_time': request.args.get('time', '0')
        })
    elif operation == 'decrypt':
        context.update({
            'encrypted_filename': request.args.get('encrypted', 'unknown'),
            'decrypted_filename': request.args.get('decrypted', 'unknown'),
            'file_size': request.args.get('size', '0'),
            'timestamp': request.args.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        })
    elif operation == 'error':
        context.update({
            'error_message': request.args.get('message', 'Unknown error'),
            'error_details': request.args.get('details', 'No details available'),
            'error_type': request.args.get('type', 'general')
        })
    
    context['operation'] = operation
    return render_template('results.html', **context)


@main_bp.route('/update-security', methods=['POST'])
@limiter.limit("5 per minute")
def update_security():
    """Update security settings."""
    if not SessionManager.validate_session():
        flash('Session expired.', 'warning')
        return redirect(url_for('main.index'))
    
    form = SecuritySettingsForm()
    
    if form.validate_on_submit():
        session['security_settings'] = {
            'encryption_algorithm': form.encryption_algorithm.data,
            'key_derivation': form.key_derivation.data,
            'session_timeout': form.session_timeout.data,
            'require_2fa': form.require_2fa.data
        }
        flash('Security settings updated successfully.', 'success')
    
    return redirect(url_for('main.security'))


# ────────────────────────────────────────────────
# Error handlers (main blueprint)
# ────────────────────────────────────────────────

@main_bp.app_errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template('404.html'), 404


@main_bp.app_errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    current_app.logger.error(f'500 Error: {error}')
    import uuid
    error_id = str(uuid.uuid4())[:8].upper()
    current_app.logger.error(f'Error ID: {error_id}')
    return render_template('500.html', error_id=error_id), 500


# ────────────────────────────────────────────────
# API routes
# ────────────────────────────────────────────────

@api_bp.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


@api_bp.route('/encrypt', methods=['POST'])
@limiter.limit("30 per minute")
def api_encrypt():
    """API endpoint for encryption."""
    try:
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'error': 'No password provided'}), 400
        
        filepath, error = save_uploaded_file(file)
        if error:
            return jsonify({'error': error}), 400
        
        try:
            salt = key_manager.generate_salt()
            key = key_manager.derive_key(password, salt)
            plaintext = FileHandler.read_file(filepath)
            nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
            
            import base64
            result = {
                'encrypted_data': base64.b64encode(ciphertext).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'algorithm': 'aes-256-gcm',
                'kdf': 'argon2id'
            }
            
            return jsonify(result)
            
        finally:
            cleanup_temp_file(filepath)
            if 'key' in locals():
                key = b'\x00' * len(key)
    
    except Exception as e:
        logger.error(f"API encryption error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': e.description.split(' ')[-1]
    }), 429


# Helper functions used in routes

def get_strength_category(strength: float) -> str:
    if strength < 0.3:
        return 'Very Weak'
    elif strength < 0.5:
        return 'Weak'
    elif strength < 0.7:
        return 'Moderate'
    elif strength < 0.9:
        return 'Strong'
    else:
        return 'Very Strong'


def get_password_suggestions(password: str) -> list:
    suggestions = []
    if len(password) < 12:
        suggestions.append('Use at least 12 characters')
    if not any(c.isupper() for c in password):
        suggestions.append('Add uppercase letters')
    if not any(c.islower() for c in password):
        suggestions.append('Add lowercase letters')
    if not any(c.isdigit() for c in password):
        suggestions.append('Add numbers')
    if not any(not c.isalnum() for c in password):
        suggestions.append('Add special characters (!@#$%^&*)')
    return suggestions