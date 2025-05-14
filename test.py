
from flask import Flask, jsonify, request
from flask_firewall import Firewall
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
firewall = Firewall(app)

# Block specific malicious IPs
firewall.block_ips([
    '192.168.1.100',
    '10.0.0.50',
    '172.16.0.25',
    '203.0.113.10'
])

# Add logging middleware for blocked requests
def log_blocked_request(request):
    logger.info(f"Blocked request from {request.remote_addr} to {request.path}")

firewall.block_ips(['192.168.1.100'], middlewares=(log_blocked_request,))

# Home route
@app.route('/')
def home():
    return jsonify({
        "message": "Welcome to the secure app",
        "status": "success",
        "endpoint": "home"
    })

# User profile route
@app.route('/profile/<username>')
def profile(username):
    return jsonify({
        "message": f"Profile for {username}",
        "status": "success",
        "endpoint": "profile"
    })

# API data route
@app.route('/api/data')
def data():
    return jsonify({
        "message": "Sample API data",
        "data": {"id": 1, "value": "secure"},
        "status": "success",
        "endpoint": "data"
    })

# Health check route
@app.route('/health')
def health():
    return jsonify({
        "message": "Server is healthy",
        "status": "success",
        "endpoint": "health"
    })

# Custom error handler for 403 responses
def custom_error_handler(e):
    logger.error(f"Firewall blocked request: {str(e)}")
    return jsonify({
        "error": "Access Denied",
        "details": str(e),
        "status": "failed"
    }), 403

firewall.set_error_handler(custom_error_handler)

# Additional routes for testing
@app.route('/info')
def info():
    return jsonify({
        "message": "Information page",
        "status": "success",
        "endpoint": "info"
    })

@app.route('/about')
def about():
    return jsonify({
        "message": "About the secure app",
        "status": "success",
        "endpoint": "about"
    })

@app.route('/contact', methods=['POST'])
def contact():
    data = request.get_json() or {}
    return jsonify({
        "message": "Contact form submitted",
        "received": data,
        "status": "success",
        "endpoint": "contact"
    })

# Run the app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)