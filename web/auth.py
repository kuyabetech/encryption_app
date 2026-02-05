"""
Authentication and session security for web interface.
"""

import secrets
import time
from typing import Optional, Dict, Any
from flask import session, request, current_app
from werkzeug.security import check_password_hash, generate_password_hash


class SessionManager:
    """Manages secure user sessions."""
    
    @staticmethod
    def create_session(user_id: str, user_data: Dict[str, Any]) -> str:
        """
        Create a new secure session.
        
        Args:
            user_id: Unique user identifier
            user_data: User data to store in session
            
        Returns:
            str: Session ID
        """
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Store session data
        session['user_id'] = user_id
        session['session_id'] = session_id
        session['created_at'] = time.time()
        session['last_activity'] = time.time()
        session['ip_address'] = request.remote_addr
        session['user_agent'] = request.user_agent.string
        session.update(user_data)
        
        # Make session permanent
        session.permanent = True
        
        current_app.logger.info(f"Session created for user: {user_id}")
        return session_id
    
    @staticmethod
    def validate_session() -> bool:
        """
        Validate current session.
        
        Returns:
            bool: True if session is valid
        """
        # Check required session data
        required_fields = ['user_id', 'session_id', 'created_at', 'last_activity']
        if not all(field in session for field in required_fields):
            return False
        
        # Check session expiration
        session_lifetime = current_app.config['PERMANENT_SESSION_LIFETIME']
        if time.time() - session.get('last_activity', 0) > session_lifetime.total_seconds():
            current_app.logger.warning(f"Session expired for user: {session.get('user_id')}")
            return False
        
        # Update last activity
        session['last_activity'] = time.time()
        
        return True
    
    @staticmethod
    def destroy_session():
        """Destroy current session."""
        user_id = session.get('user_id')
        session.clear()
        current_app.logger.info(f"Session destroyed for user: {user_id}")
    
    @staticmethod
    def get_csrf_token() -> str:
        """
        Generate or retrieve CSRF token.
        
        Returns:
            str: CSRF token
        """
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    @staticmethod
    def validate_csrf_token(token: Optional[str]) -> bool:
        """
        Validate CSRF token.
        
        Args:
            token: CSRF token to validate
            
        Returns:
            bool: True if token is valid
        """
        if not token:
            return False
        
        expected_token = session.get('csrf_token')
        if not expected_token:
            return False
        
        # Use constant-time comparison
        return secrets.compare_digest(token, expected_token)


class RateLimiter:
    """Simple in-memory rate limiter (use Redis in production)."""
    
    _attempts: Dict[str, list] = {}
    
    @classmethod
    def check_limit(cls, identifier: str, limit: int, window: int) -> bool:
        """
        Check if rate limit is exceeded.
        
        Args:
            identifier: User identifier (IP, user_id, etc.)
            limit: Number of allowed attempts
            window: Time window in seconds
            
        Returns:
            bool: True if allowed, False if rate limited
        """
        now = time.time()
        
        # Clean old attempts
        if identifier in cls._attempts:
            cls._attempts[identifier] = [
                t for t in cls._attempts[identifier]
                if now - t < window
            ]
        
        # Check if limit exceeded
        if identifier not in cls._attempts:
            cls._attempts[identifier] = []
        
        if len(cls._attempts[identifier]) >= limit:
            return False
        
        # Record attempt
        cls._attempts[identifier].append(now)
        return True
    
    @classmethod
    def get_remaining(cls, identifier: str, limit: int, window: int) -> int:
        """
        Get remaining attempts.
        
        Args:
            identifier: User identifier
            limit: Maximum attempts
            window: Time window in seconds
            
        Returns:
            int: Remaining attempts
        """
        now = time.time()
        
        if identifier not in cls._attempts:
            return limit
        
        # Count attempts within window
        recent_attempts = [
            t for t in cls._attempts[identifier]
            if now - t < window
        ]
        
        return max(0, limit - len(recent_attempts))


class PasswordManager:
    """Manages password security for web interface."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using Argon2.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        # Use Argon2 if available
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.hash(password)
        except ImportError:
            # Fallback to Werkzeug's PBKDF2
            return generate_password_hash(password, method='pbkdf2:sha256:600000')
    
    @staticmethod
    def verify_password(hashed_password: str, password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            hashed_password: Hashed password
            password: Plain text password to verify
            
        Returns:
            bool: True if password matches
        """
        try:
            # Try Argon2 first
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.verify(hashed_password, password)
        except ImportError:
            # Fallback to Werkzeug
            return check_password_hash(hashed_password, password)
        except Exception:
            return False