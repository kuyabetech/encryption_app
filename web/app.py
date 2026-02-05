"""
Flask web application for secure file encryption.
"""

import os
import secrets
import tempfile
from pathlib import Path
from datetime import timedelta
from typing import Optional

from flask import (
    Flask,
    request,
    jsonify,
    make_response,
    session,
    redirect,
    url_for,
    flash,
    render_template,
)
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Optional: more advanced security headers
try:
    from flask_talisman import Talisman
    TALISMAN_AVAILABLE = True
except ImportError:
    TALISMAN_AVAILABLE = False

# Load environment variables
load_dotenv()


def create_app(config: Optional[dict] = None) -> Flask:
    """
    Create and configure the Flask application.
    
    Args:
        config: Optional configuration overrides
        
    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # ────────────────────────────────────────────────
    # Core configuration
    # ────────────────────────────────────────────────

    app.config.update(
        # Security
        SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True').lower() in ('true', '1', 'yes'),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 1800))
        ),

        # File handling
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 100 * 1024 * 1024)),  # 100 MB default
        UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', os.path.join(app.root_path, 'uploads')),

        # Session
        SESSION_TYPE='filesystem',
        SESSION_FILE_DIR=tempfile.mkdtemp(),
        SESSION_PERMANENT=False,
        SESSION_USE_SIGNER=True,

        # Forms / CSRF
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
    )

    if config:
        app.config.update(config)

    # Ensure upload directory exists with restrictive permissions
    upload_dir = Path(app.config['UPLOAD_FOLDER'])
    upload_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(upload_dir, 0o700)  # owner only
    except:
        pass

    # ────────────────────────────────────────────────
    # Initialize extensions
    # ────────────────────────────────────────────────

    csrf = CSRFProtect(app)
    Session(app)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[os.getenv('RATELIMIT_DEFAULT', '100/hour')],
        storage_uri='memory://',  # ← Change to redis:// in production
    )

    # Content Security Policy (if Talisman is installed)
    if TALISMAN_AVAILABLE:
        csp = {
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'"],  # remove unsafe-inline in prod if possible
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'frame-ancestors': "'none'",
        }
        Talisman(app,
                 content_security_policy=csp,
                 force_https=app.config['SESSION_COOKIE_SECURE'],
                 strict_transport_security=True,
                 session_cookie_secure=app.config['SESSION_COOKIE_SECURE'])

    # ────────────────────────────────────────────────
    # Register blueprints
    # ────────────────────────────────────────────────

    from web.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    # ────────────────────────────────────────────────
    # Global request & response handlers
    # ────────────────────────────────────────────────

    @app.before_request
    def enforce_file_size_limit():
        """Reject oversized requests early."""
        if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            app.logger.warning(f"Request too large: {request.content_length} bytes")
            return jsonify({"error": "File too large"}), 413

    @app.after_request
    def apply_security_and_nocache_headers(response):
        """
        Apply security headers to all responses
        + no-cache on sensitive routes
        """
        path = request.path

        # No-cache on pages that handle encryption/decryption/download
        if path in {'/encrypt', '/decrypt', '/download'} or path.startswith('/api/v1'):
            response.headers.update({
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0, private',
                'Pragma': 'no-cache',
                'Expires': '0',
            })

        # Security headers (applied to every response)
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',  # modern default
        })

        return response

    # ────────────────────────────────────────────────
    # Error handlers
    # ────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404   # ← better than JSON for web UI

    @app.errorhandler(413)
    def file_too_large(error):
        return jsonify({"error": "File too large"}), 413

    @app.errorhandler(429)
    def ratelimit_exceeded(error):
        return jsonify({"error": "Rate limit exceeded"}), 429

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Server error: {error}", exc_info=True)
        return render_template('500.html'), 500   # ← better for web UI

    return app


# Create and run the application
app = create_app()

if __name__ == '__main__':
    app.run(
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV', 'development') == 'development',
        threaded=True,  # better for development
    )