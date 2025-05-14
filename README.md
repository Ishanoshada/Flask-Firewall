

# Flask-firewall

**Flask-firewall** is a powerful and easy-to-use firewall middleware for Flask applications, designed to protect against common web threats. It provides a wide range of security rules, including IP filtering, rate limiting, reCAPTCHA verification, XSS prevention, and more. Whether you're securing a small web app or a large API, Flask-firewall makes it simple to add robust security with minimal setup.

[![PyPI version](https://badge.fury.io/py/flask-firewall.svg)](https://badge.fury.io/py/flask-firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## Features

- **Simple Setup**: Add security to your Flask app with just a few lines of code.
- **Comprehensive Rules**: Protect against XSS, SQL injection, path traversal, bots, and more.
- **reCAPTCHA Support**: Prevent bot abuse with Google reCAPTCHA, configured once.
- **Rate Limiting**: IP-based and session-based limits to stop DoS attacks.
- **Flexible Configuration**: Apply rules globally or to specific routes using decorators.
- **Middleware Support**: Extend rules with custom logic.
- **Structured Logging**: JSON logs for integration with tools like ELK or Splunk.
- **Bypass Mechanism**: Allow trusted clients to skip rules with a secret key.

## Installation

Install Flask-firewall using pip:

```bash
pip install flask-firewall
```

### Requirements

- Python 3.8 or higher
- Flask 2.0.0 or higher
- requests 2.25.0 or higher (for reCAPTCHA)
- pytz 2021.1 or higher (for time-based rules)

## Usage

### Basic Usage
Get started with Flask-firewall in minutes. Here's a simple example that blocks specific IPs and limits request rates:

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Block specific IPs
firewall.block_ips(['192.168.1.100'])

# Limit requests to 100 per minute per IP
firewall.rate_limit(limit=100, period=60)

@app.route('/hello')
def hello():
    return jsonify({"message": "Hello, secure world!"})

if __name__ == '__main__':
    app.run(debug=True)
```

This setup blocks requests from `192.168.1.100` and ensures no IP sends more than 100 requests per minute.

### Using reCAPTCHA
To protect against bots, add Google reCAPTCHA verification. Set the secret key once when initializing the firewall:

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
# Set reCAPTCHA secret key once
firewall = Firewall(app, recaptcha_secret_key='your-recaptcha-secret-key')

# Apply reCAPTCHA, exempting certain routes
firewall.recaptcha(exempt_routes=['/public'])

@app.route('/submit', methods=['POST'])
def submit():
    return jsonify({"message": "Form submitted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Frontend Example** (for reCAPTCHA):

```html
<form method="POST" action="/submit">
    <div class="g-recaptcha" data-sitekey="your_site_key_here"></div>
    <button type="submit">Submit</button>
</form>
<script src="https://www.google.com/recaptcha/api.js"></script>
```

**JavaScript** (to send reCAPTCHA token):

```javascript
grecaptcha.ready(function() {
    grecaptcha.execute('your_site_key_here', {action: 'submit'}).then(function(token) {
        fetch('/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ recaptcha_token: token })
        }).then(response => response.json()).then(data => console.log(data));
    });
});
```

Obtain your reCAPTCHA site key and secret key from [Google reCAPTCHA](https://www.google.com/recaptcha).

### Protecting Specific Routes
Use the `@firewall.protect` decorator to apply rules to individual routes:

```python
@app.route('/admin', methods=['GET'])
@firewall.protect(rules=[
    firewall.RestrictedPathRule(['/admin'], allowed_ips=['127.0.0.1']),
    firewall.HoneypotRule(['honeypot_field'])
])
def admin():
    return jsonify({"message": "Admin access granted"})
```

## Available Rules

Flask-firewall offers 27 security rules to protect your application:

| Rule | Description | Example Usage |
|------|-------------|---------------|
| `IPRule` | Allow or block specific IPs or ranges | `firewall.allow_ips(['127.0.0.1'])` |
| `RateLimitRule` | Limit requests per IP | `firewall.rate_limit(limit=100, period=60)` |
| `SessionRateLimitRule` | Limit requests per session token | `firewall.session_rate_limit(limit=50, period=60)` |
| `XSSRule` | Block XSS attempts | `firewall.protect_from_xss()` |
| `SQLInjectionRule` | Block SQL injection attempts | `firewall.protect_from_sql_injection()` |
| `PathTraversalRule` | Block path traversal attacks | `firewall.protect_from_path_traversal()` |
| `CSRFProtectionRule` | Enforce CSRF token validation | `firewall.csrf_protection(exempt_routes=['/api'])` |
| `MethodRule` | Restrict HTTP methods | `firewall.restrict_methods(['GET', 'POST'])` |
| `ReferrerRule` | Restrict referrers | `firewall.restrict_referrers(['example.com'])` |
| `ContentTypeRule` | Restrict content types | `firewall.restrict_content_types(['application/json'])` |
| `UserAgentRule` | Allow or block user agents | `firewall.allow_user_agent(['Mozilla'])` |
| `RequestSizeRule` | Limit request size | `firewall.limit_request_size(max_size=2*1024*1024)` |
| `OriginRule` | Restrict origins | `firewall.restrict_origins(['https://example.com'])` |
| `HeaderRule` | Forbid specific headers | `firewall.forbid_headers(['X-Debug-Mode'])` |
| `HostRule` | Restrict hosts | `firewall.restrict_hosts(['example.com'])` |
| `RequestBodyRule` | Validate JSON request bodies | `firewall.validate_json_body(['user_id'])` |
| `TimeBasedRule` | Restrict access by time | `firewall.restrict_time(9, 17, 'UTC')` |
| `CustomRegexRule` | Match custom regex patterns | `firewall.custom_regex([r'admin.*login'])` |
| `CommandInjectionRule` | Block command injection attempts | `firewall.protect_from_command_injection()` |
| `APIKeyRule` | Require valid API keys | `firewall.require_api_key(lambda key: key == 'secret')` |
| `SecureConnectionRule` | Enforce HTTPS | `firewall.enforce_https()` |
| `RestrictedPathRule` | Restrict paths by IP | `firewall.restrict_paths(['/admin'], ['192.168.1.1'])` |
| `ParameterValidationRule` | Validate parameters | `firewall.validate_parameters({'user_id': lambda x: x.isdigit()})` |
| `HeaderValidationRule` | Validate headers | `firewall.validate_headers({'Content-Type': lambda x: x == 'application/json'})` |
| `MethodPathRule` | Restrict methods per path | `firewall.restrict_methods_for_paths({'/login': ['POST']})` |
| `RecaptchaRule` | Require reCAPTCHA verification | `firewall.recaptcha(exempt_routes=['/public'])` |
| `ProtocolVersionRule` | Restrict HTTP protocol versions | `firewall.restrict_protocol(['HTTP/2.0'])` |
| `HoneypotRule` | Detect bots via honeypot fields | `firewall.add_honeypot(['honeypot_field'])` |


## Example Applications

Below are 8 example applications demonstrating how to use Flask-Firewall in various scenarios. Each example includes a complete Flask app with firewall rules tailored to specific use cases.

### 1. Basic IP Blocking
Protect a simple web app by blocking specific IP addresses.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Block malicious IPs
firewall.block_ips(['192.168.1.100', '10.0.0.50'])

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the secure app"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Ideal for small apps needing to block known malicious IPs without complex setup.

### 2. Rate-Limited Public API
Secure a public API with rate limiting to prevent abuse.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Limit to 50 requests per minute per IP
firewall.rate_limit(limit=50, period=60)

@app.route('/api/data')
def get_data():
    return jsonify({"data": "Sample API response"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Protects APIs from DoS attacks or excessive usage by limiting requests per IP.

### 3. reCAPTCHA-Protected Form
Prevent bots from submitting forms using reCAPTCHA.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app, recaptcha_secret_key='your-recaptcha-secret-key')

# Apply reCAPTCHA to all routes except /info
firewall.recaptcha(exempt_routes=['/info'])

@app.route('/submit', methods=['POST'])
def submit():
    return jsonify({"message": "Form submitted successfully"})

@app.route('/info')
def info():
    return jsonify({"message": "Public info page"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Frontend** (add to `templates/form.html`):
```html
<form method="POST" action="/submit">
    <div class="g-recaptcha" data-sitekey="your_site_key_here"></div>
    <button type="submit">Submit</button>
</form>
<script src="https://www.google.com/recaptcha/api.js"></script>
```

**Use Case**: Secures contact forms or login pages against automated bot submissions.

### 4. Admin Dashboard with Restricted Access
Restrict access to an admin dashboard to specific IPs.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Restrict /admin to trusted IPs
firewall.restrict_paths(['/admin'], allowed_ips=['127.0.0.1', '192.168.1.1'])

@app.route('/admin')
def admin():
    return jsonify({"message": "Admin dashboard"})

@app.route('/')
def home():
    return jsonify({"message": "Public page"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Ensures sensitive admin routes are only accessible from trusted networks.

### 5. Secure File Upload
Limit file uploads by content type and size to prevent abuse.

```python
from flask import Flask, request, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Restrict to image uploads, max 2MB
firewall.restrict_content_types(['image/jpeg', 'image/png'])
firewall.limit_request_size(max_size=2*1024*1024)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    return jsonify({"message": f"Uploaded {file.filename}"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Secures file upload endpoints, common in content management systems.

### 6. Time-Restricted Access
Allow access only during business hours (e.g., 9 AM to 5 PM UTC).

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Restrict access to 9 AM - 5 PM UTC
firewall.restrict_time(start_hour=9, end_hour=17, timezone='UTC')

@app.route('/business')
def business():
    return jsonify({"message": "Business portal"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Useful for applications that should only be accessible during specific hours.

### 7. API Key Authentication
Require a valid API key for secure endpoints.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Validate API key
firewall.require_api_key(lambda key: key == 'my-secret-key', header='X-API-Key')

@app.route('/secure')
def secure():
    return jsonify({"message": "Secure data"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Protects sensitive API endpoints, such as those handling user data.

### 8. XSS and SQL Injection Protection
Protect a web app from XSS and SQL injection attacks.

```python
from flask import Flask, jsonify
from flask_firewall import Firewall

app = Flask(__name__)
firewall = Firewall(app)

# Block XSS and SQL injection attempts
firewall.protect_from_xss()
firewall.protect_from_sql_injection()

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return jsonify({"results": f"Searched for {query}"})

if __name__ == '__main__':
    app.run(debug=True)
```

**Use Case**: Secures user input forms or search endpoints against malicious payloads.


## Advanced Configuration

### Middleware Functions
Add custom logic to rules with middleware functions:

```python
def log_request(request):
    current_app.logger.info(f"Request from {request.remote_addr}")

firewall.rate_limit(middlewares=(log_request,))
```

### Bypass Key
Allow trusted clients to bypass rules with a secret key:

```python
firewall.set_bypass_key('supersecret')

# Request with header: X-Firewall-Bypass: supersecret
```

### Custom Error Handling
Define a custom error handler for 403 responses:

```python
def custom_error_handler(e):
    return jsonify({"error": "Access Denied", "details": str(e)}), 403

firewall.set_error_handler(custom_error_handler)
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository: `https://github.com/Ishanoshada/flask_firewall`
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request

Please include tests and update documentation for new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: Ishan Oshada
- **Email**: ic31908@gmail.com
- **GitHub**: [Ishanoshada](https://github.com/Ishanoshada)
- **Issues**: [GitHub Issues](https://github.com/Ishanoshada/flask_firewall/issues)

