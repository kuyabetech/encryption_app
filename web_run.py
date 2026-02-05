#!/usr/bin/env python3
"""
Run the Flask web application.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Set environment variables
os.environ['FLASK_APP'] = 'web.app:app'
os.environ['FLASK_ENV'] = 'development'
os.environ['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Ensure uploads directory exists
uploads_dir = Path(__file__).parent / 'web' / 'uploads'
uploads_dir.mkdir(parents=True, exist_ok=True)

print("🚀 Starting Secure Encryption Web Interface")
print("="*50)
print(f"📁 Uploads directory: {uploads_dir}")
print("🌐 Open http://localhost:5000 in your browser")
print("="*50)

# Import and run the app
from web.app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)