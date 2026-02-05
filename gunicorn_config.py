# gunicorn_config.py
import multiprocessing
import os

# Server socket
bind = os.getenv('GUNICORN_BIND', '0.0.0.0:5000')
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'warning'

# Process naming
proc_name = 'secure_encrypt_web'

# SSL (uncomment for HTTPS)
# keyfile = '/path/to/key.pem'
# certfile = '/path/to/cert.pem'