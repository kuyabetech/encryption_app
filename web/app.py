"""
Flask web application for secure file encryption.
"""

import os
import secrets
import tempfile
from pathlib import Path
from datetime import timedelta
from typing import Optional

from flask import Flask
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Optional security headers
try:
    from flask_talisman import Talisman
    TALISMAN_AVAILABLE = True
except ImportError:
    TALISMAN_AVAILABLE = False


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
    
    # Default configuration
    app.config.update(
        # Security
        SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 1800))
        ),
        
        # File uploads
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH', 100 * 1024 * 1024)),
        UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', os.path.join(app.root_path, 'uploads')),
        
        # Session configuration
        SESSION_TYPE='filesystem',
        SESSION_FILE_DIR=tempfile.mkdtemp(),
        SESSION_PERMANENT=False,
        SESSION_USE_SIGNER=True,
        
        # Flask-WTF
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
    )
    
    # Override with custom config
    if config:
        app.config.update(config)
    
    # Ensure upload directory exists
    upload_dir = Path(app.config['UPLOAD_FOLDER'])
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize extensions
    csrf = CSRFProtect(app)
    Session(app)
    
    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[os.getenv('RATELIMIT_DEFAULT', '100/hour')],
        storage_uri='memory://',  # Use Redis in production
    )
    
    # Security headers (optional)
    if TALISMAN_AVAILABLE:
        csp = {
            'default-src': "'self'",
            'style-src': ["'self'", "'unsafe-inline'"],
            'script-src': ["'self'"],
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'"],
        }
        Talisman(app, content_security_policy=csp)
    
    # Register blueprints
    from web.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Error handlers
    register_error_handlers(app)
    
    # Request handlers
    register_request_handlers(app)
    
    # Security middleware
    add_security_headers(app)
    
    return app


def register_error_handlers(app: Flask):
    """Register custom error handlers."""
    
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Resource not found"}, 404
    
    @app.errorhandler(413)
    def file_too_large(error):
        return {"error": "File too large"}, 413
    
    @app.errorhandler(429)
    def ratelimit_exceeded(error):
        return {"error": "Rate limit exceeded"}, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Server error: {error}")
        return {"error": "Internal server error"}, 500


def register_request_handlers(app: Flask):
    """Register request handlers for security."""
    
    @app.before_request
    def check_file_size():
        """Ensure file size is within limits."""
        from flask import request
        if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
            app.logger.warning(f"File too large: {request.content_length} bytes")
            return {"error": "File too large"}, 413
    
    @app.after_request
    def add_no_cache_headers(response):
        """Add no-cache headers for sensitive pages."""
        if request.path in ['/encrypt', '/decrypt', '/download']:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response


def add_security_headers(app: Flask):
    """Add additional security headers."""
    
    @app.after_request
    def security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Clickjacking protection
        response.headers['X-Frame-Options'] = 'DENY'
        
        # XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions policy
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response


# Create app instance
app = create_app()

if __name__ == '__main__':
    # Development server
    app.run(
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', 5000)),
        debug=(os.getenv('FLASK_ENV', 'development') == 'development')
    )