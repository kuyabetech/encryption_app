#!/bin/bash
# setup-web.sh

echo "🔐 Setting up Secure Encryption Web Interface..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-web.txt

# Create necessary directories
mkdir -p web/uploads web/static/css web/static/js web/templates logs

# Set permissions (Unix)
chmod 700 web/uploads
chmod 600 .env 2>/dev/null || true

# Generate secret key
if [ ! -f .env ]; then
    echo "FLASK_APP=web.app" > .env
    echo "FLASK_ENV=development" >> .env
    echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
    echo "UPLOAD_FOLDER=./web/uploads" >> .env
    echo "MAX_CONTENT_LENGTH=104857600" >> .env
    echo ".env file created with secret key"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the web server:"
echo "  source venv/bin/activate"
echo "  flask run --host=0.0.0.0 --port=5000"
echo ""
echo "Or for production:"
echo "  gunicorn web.app:app --bind 0.0.0.0:5000 --workers 4"
echo ""
echo "📁 Uploads directory: web/uploads/"
echo "📁 Logs directory: logs/"