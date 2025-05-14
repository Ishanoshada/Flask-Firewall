import re
import ipaddress
import json
import requests
from functools import wraps
from urllib.parse import urlparse
from flask import request, abort, current_app, jsonify
from time import time
from datetime import datetime
import pytz

class FirewallException(Exception):
    """Exception raised for firewall rule violations."""
    pass

class FirewallRule:
    """Base class for firewall rules."""
    
    def __init__(self, action='block', middlewares=None):
        """
        Initialize a firewall rule.
        
        Args:
            action (str): Action to take when rule is triggered ('block', 'allow', or 'log').
            middlewares (tuple): Optional middleware functions to process the request.
        """
        if action not in ('block', 'allow', 'log'):
            raise ValueError("Action must be one of: 'block', 'allow', 'log'")
        self.action = action
        self.middlewares = middlewares or ()
    
    def check(self, request):
        """
        Check if request violates the rule.
        
        Args:
            request: Flask request object
            
        Returns:
            bool: True if rule is triggered, False otherwise
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_violation_message(self):
        """Get the violation message for this rule."""
        return f"Request blocked by {self.__class__.__name__}"
    
    def apply_middlewares(self, request):
        """Apply middleware functions to the request."""
        if not self.middlewares:
            return
        for middleware in self.middlewares:
            try:
                middleware(request)
            except Exception as e:
                current_app.logger.error(f"Middleware {middleware.__name__} failed: {str(e)}")
                raise FirewallException(f"Middleware error: {str(e)}")

class IPRule(FirewallRule):
    """Rule to allow or block specific IP addresses or ranges."""
    
    def __init__(self, ip_list, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.networks = []
        for ip in ip_list:
            try:
                if '/' in ip:
                    self.networks.append(ipaddress.ip_network(ip, strict=False))
                else:
                    self.networks.append(ipaddress.ip_address(ip))
            except ValueError:
                current_app.logger.warning(f"Invalid IP address or network: {ip}")
    
    def check(self, request):
        self.apply_middlewares(request)
        client_ip = ipaddress.ip_address(request.remote_addr)
        for network in self.networks:
            if isinstance(network, ipaddress.IPv4Network) or isinstance(network, ipaddress.IPv6Network):
                if client_ip in network:
                    return True
            elif client_ip == network:
                return True
        return False
    
    def get_violation_message(self):
        return f"IP address {request.remote_addr} is {'blocked' if self.action == 'block' else 'allowed' if self.action == 'allow' else 'logged'}"

class RateLimitRule(FirewallRule):
    """Rule to limit request rate from a single IP."""
    
    def __init__(self, limit=100, period=60, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.limit = limit
        self.period = period
        self._request_counts = {}
        self._cleanup_counter = 0
    
    def check(self, request):
        self.apply_middlewares(request)
        current_time = time()
        client_ip = request.remote_addr
        
        self._cleanup_counter += 1
        if self._cleanup_counter > 1000:
            self._cleanup()
            self._cleanup_counter = 0
        
        if client_ip not in self._request_counts:
            self._request_counts[client_ip] = [(current_time, 1)]
            return False
        
        count = 0
        for timestamp, req_count in self._request_counts[client_ip]:
            if current_time - timestamp <= self.period:
                count += req_count
        
        self._request_counts[client_ip].append((current_time, 1))
        return count > self.limit
    
    def _cleanup(self):
        current_time = time()
        for ip in list(self._request_counts.keys()):
            self._request_counts[ip] = [
                (ts, count) for ts, count in self._request_counts[ip]
                if current_time - ts <= self.period
            ]
            if not self._request_counts[ip]:
                del self._request_counts[ip]
    
    def get_violation_message(self):
        return f"Rate limit exceeded: {self.limit} requests per {self.period} seconds"

class SessionRateLimitRule(FirewallRule):
    """Rule to limit request rate based on a session identifier (e.g., API key or session token)."""
    
    def __init__(self, limit=50, period=60, session_key_header='X-Session-Token', action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.limit = limit
        self.period = period
        self.session_key_header = session_key_header
        self._request_counts = {}
        self._cleanup_counter = 0
    
    def check(self, request):
        self.apply_middlewares(request)
        current_time = time()
        session_key = request.headers.get(self.session_key_header) or request.args.get('session_key')
        if not session_key:
            return False
        
        self._cleanup_counter += 1
        if self._cleanup_counter > 1000:
            self._cleanup()
            self._cleanup_counter = 0
        
        if session_key not in self._request_counts:
            self._request_counts[session_key] = [(current_time, 1)]
            return False
        
        count = 0
        for timestamp, req_count in self._request_counts[session_key]:
            if current_time - timestamp <= self.period:
                count += req_count
        
        self._request_counts[session_key].append((current_time, 1))
        return count > self.limit
    
    def _cleanup(self):
        current_time = time()
        for key in list(self._request_counts.keys()):
            self._request_counts[key] = [
                (ts, count) for ts, count in self._request_counts[key]
                if current_time - ts <= self.period
            ]
            if not self._request_counts[key]:
                del self._request_counts[key]
    
    def get_violation_message(self):
        return f"Session rate limit exceeded: {self.limit} requests per {self.period} seconds"

class XSSRule(FirewallRule):
    """Rule to detect and block XSS attempts."""
    
    def __init__(self, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.patterns = [
            re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'document\.cookie', re.IGNORECASE),
            re.compile(r'document\.location', re.IGNORECASE),
            re.compile(r'document\.write', re.IGNORECASE),
            re.compile(r'<iframe', re.IGNORECASE),
            re.compile(r'alert\s*\(', re.IGNORECASE),
        ]
    
    def check(self, request):
        self.apply_middlewares(request)
        for key, value in request.args.items():
            if self._check_value(value):
                return True
        for key, value in request.form.items():
            if self._check_value(value):
                return True
        for key, value in request.cookies.items():
            if self._check_value(value):
                return True
        headers_to_check = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in headers_to_check:
            if header in request.headers and self._check_value(request.headers[header]):
                return True
        return False
    
    def _check_value(self, value):
        if not isinstance(value, str):
            return False
        for pattern in self.patterns:
            if pattern.search(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Potential XSS attack detected"

class SQLInjectionRule(FirewallRule):
    """Rule to detect and block SQL injection attempts."""
    
    def __init__(self, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.patterns = [
            re.compile(r';\s*SELECT\s+', re.IGNORECASE),
            re.compile(r';\s*INSERT\s+', re.IGNORECASE),
            re.compile(r';\s*UPDATE\s+', re.IGNORECASE),
            re.compile(r';\s*DELETE\s+', re.IGNORECASE),
            re.compile(r';\s*DROP\s+', re.IGNORECASE),
            re.compile(r'UNION\s+SELECT\s+', re.IGNORECASE),
            re.compile(r'--\s+', re.IGNORECASE),
            re.compile(r'/\*.*?\*/', re.IGNORECASE | re.DOTALL),
            re.compile(r'EXEC\s+\w+', re.IGNORECASE),
            re.compile(r'xp_\w+', re.IGNORECASE),
        ]
    
    def check(self, request):
        self.apply_middlewares(request)
        for key, value in request.args.items():
            if self._check_value(value):
                return True
        for key, value in request.form.items():
            if self._check_value(value):
                return True
        return False
    
    def _check_value(self, value):
        if not isinstance(value, str):
            return False
        for pattern in self.patterns:
            if pattern.search(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Potential SQL injection attack detected"

class PathTraversalRule(FirewallRule):
    """Rule to detect and block path traversal attacks."""
    
    def __init__(self, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.patterns = [
            re.compile(r'\.\./', re.IGNORECASE),
            re.compile(r'\.\.\\', re.IGNORECASE),
            re.compile(r'%2e%2e%2f', re.IGNORECASE),
            re.compile(r'%2e%2e/', re.IGNORECASE),
            re.compile(r'\.\.%2f', re.IGNORECASE),
            re.compile(r'/etc/passwd', re.IGNORECASE),
            re.compile(r'c:\\windows', re.IGNORECASE),
            re.compile(r'cmd\.exe', re.IGNORECASE),
            re.compile(r'/bin/sh', re.IGNORECASE),
        ]
    
    def check(self, request):
        self.apply_middlewares(request)
        if self._check_value(request.path):
            return True
        for key, value in request.args.items():
            if self._check_value(value):
                return True
        for key, value in request.form.items():
            if self._check_value(value):
                return True
        return False
    
    def _check_value(self, value):
        if not isinstance(value, str):
            return False
        for pattern in self.patterns:
            if pattern.search(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Potential path traversal attack detected"

class CSRFProtectionRule(FirewallRule):
    """Rule to enforce CSRF token validation for state-changing requests."""
    
    def __init__(self, exempt_routes=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.exempt_routes = exempt_routes or []
    
    def check(self, request):
        self.apply_middlewares(request)
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return False
        for route in self.exempt_routes:
            if isinstance(route, str) and request.path == route:
                return False
            elif hasattr(route, 'match') and route.match(request.path):
                return False
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        return not token
    
    def get_violation_message(self):
        return "CSRF protection: missing or invalid token"

class MethodRule(FirewallRule):
    """Rule to restrict HTTP methods."""
    
    def __init__(self, allowed_methods=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.allowed_methods = allowed_methods or ['GET', 'POST', 'HEAD']
    
    def check(self, request):
        self.apply_middlewares(request)
        return request.method not in self.allowed_methods
    
    def get_violation_message(self):
        return f"HTTP method {request.method} is not allowed"

class ReferrerRule(FirewallRule):
    """Rule to restrict based on the Referer header."""
    
    def __init__(self, allowed_domains=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.allowed_domains = allowed_domains or []
    
    def check(self, request):
        self.apply_middlewares(request)
        if not self.allowed_domains:
            return False
        referrer = request.headers.get('Referer')
        if not referrer:
            return False
        try:
            parsed = urlparse(referrer)
            domain = parsed.netloc
            for allowed in self.allowed_domains:
                if domain == allowed or domain.endswith('.' + allowed):
                    return False
            return True
        except:
            return True
    
    def get_violation_message(self):
        return "Request from unauthorized referrer"

class ContentTypeRule(FirewallRule):
    """Rule to restrict based on Content-Type header."""
    
    def __init__(self, allowed_types=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.allowed_types = allowed_types or [
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'application/json',
            'text/plain'
        ]
    
    def check(self, request):
        self.apply_middlewares(request)
        if request.method not in ('POST', 'PUT', 'PATCH'):
            return False
        content_type = request.headers.get('Content-Type', '')
        if not content_type:
            return False
        base_content_type = content_type.split(';')[0].strip()
        return base_content_type not in self.allowed_types
    
    def get_violation_message(self):
        return "Request with unauthorized content type"

class UserAgentRule(FirewallRule):
    """Rule to check user agents based on the specified action."""
    
    def __init__(self, user_agents, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.user_agents = set(user_agents or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        user_agent = request.headers.get('User-Agent', '')
        return any(pattern in user_agent for pattern in self.user_agents)
    
    def get_violation_message(self):
        return f"Request from {'blocked' if self.action == 'block' else 'allowed' if self.action == 'allow' else 'logged'} user agent"

class RequestSizeRule(FirewallRule):
    """Rule to limit request size."""
    
    def __init__(self, max_size=1024*1024, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.max_size = max_size
    
    def check(self, request):
        self.apply_middlewares(request)
        content_length = request.headers.get('Content-Length')
        if content_length and int(content_length) > self.max_size:
            return True
        if request.content_length and request.content_length > self.max_size:
            return True
        return False
    
    def get_violation_message(self):
        return f"Request size exceeds limit of {self.max_size} bytes"

class OriginRule(FirewallRule):
    """Rule to check request origins."""
    
    def __init__(self, origins, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.origins = set(origins or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        origin = request.headers.get('Origin')
        if origin:
            return origin in self.origins
        return False
    
    def get_violation_message(self):
        return f"Request from {'blocked' if self.action == 'block' else 'allowed' if self.action == 'allow' else 'logged'} origin"

class HeaderRule(FirewallRule):
    """Rule to forbid certain headers."""
    
    def __init__(self, forbidden_headers, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.forbidden_headers = set(forbidden_headers or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        for header in self.forbidden_headers:
            if header in request.headers:
                return True
        return False
    
    def get_violation_message(self):
        return "Request contains forbidden headers"

class HostRule(FirewallRule):
    """Rule to restrict hosts."""
    
    def __init__(self, hosts, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.hosts = set(hosts or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        host = request.host
        return host in self.hosts
    
    def get_violation_message(self):
        return f"Request from {'blocked' if self.action == 'block' else 'allowed' if self.action == 'allow' else 'logged'} host"

class RequestBodyRule(FirewallRule):
    """Rule to validate JSON request bodies."""
    
    def __init__(self, required_fields=None, max_depth=5, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.required_fields = set(required_fields or [])
        self.max_depth = max_depth
    
    def check(self, request):
        self.apply_middlewares(request)
        if request.content_type != 'application/json':
            return False
        try:
            data = request.get_json()
            if not data:
                return True
            if self.required_fields:
                for field in self.required_fields:
                    if field not in data:
                        return True
            if self._check_depth(data) > self.max_depth:
                return True
        except:
            return True
        return False
    
    def _check_depth(self, obj, depth=0):
        if depth > self.max_depth:
            return depth
        if isinstance(obj, dict):
            return max(self._check_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return max(self._check_depth(v, depth + 1) for v in obj)
        return depth
    
    def get_violation_message(self):
        return "Invalid JSON request body"

class TimeBasedRule(FirewallRule):
    """Rule to restrict access based on time of day."""
    
    def __init__(self, start_hour, end_hour, timezone='UTC', action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.timezone = pytz.timezone(timezone)
    
    def check(self, request):
        self.apply_middlewares(request)
        now = datetime.now(self.timezone)
        current_hour = now.hour
        if self.start_hour <= self.end_hour:
            return self.start_hour <= current_hour <= self.end_hour
        else:
            return current_hour >= self.start_hour or current_hour <= self.end_hour
    
    def get_violation_message(self):
        return f"Access restricted outside {self.start_hour}:00-{self.end_hour}:00 {self.timezone}"

class CustomRegexRule(FirewallRule):
    """Rule to match custom regex patterns in request data."""
    
    def __init__(self, patterns, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.patterns = [re.compile(p) for p in patterns]
    
    def check(self, request):
        self.apply_middlewares(request)
        check_values = [
            request.path,
            *request.args.values(),
            *request.form.values(),
            *request.headers.values(),
        ]
        for value in check_values:
            if not isinstance(value, str):
                continue
            for pattern in self.patterns:
                if pattern.search(value):
                    return True
        return False
    
    def get_violation_message(self):
        return "Request matched custom regex pattern"

class CommandInjectionRule(FirewallRule):
    """Rule to detect and block command injection attempts."""
    
    def __init__(self, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.patterns = [
            re.compile(r'[;&|`]', re.IGNORECASE),
            re.compile(r'\$\(', re.IGNORECASE),
            re.compile(r'`.*`', re.IGNORECASE),
            re.compile(r'\|\|', re.IGNORECASE),
            re.compile(r'&&', re.IGNORECASE),
        ]
    
    def check(self, request):
        self.apply_middlewares(request)
        for key, value in request.args.items():
            if self._check_value(value):
                return True
        for key, value in request.form.items():
            if self._check_value(value):
                return True
        return False
    
    def _check_value(self, value):
        if not isinstance(value, str):
            return False
        for pattern in self.patterns:
            if pattern.search(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Potential command injection attack detected"

class APIKeyRule(FirewallRule):
    """Rule to require a valid API key in the request headers."""
    
    def __init__(self, validate_func, header='X-API-Key', action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.validate_func = validate_func
        self.header = header
    
    def check(self, request):
        self.apply_middlewares(request)
        api_key = request.headers.get(self.header)
        if not api_key or not self.validate_func(api_key):
            return True
        return False
    
    def get_violation_message(self):
        return "Invalid or missing API key"

class SecureConnectionRule(FirewallRule):
    """Rule to ensure the request is made over HTTPS."""
    
    def __init__(self, action='block', middlewares=None):
        super().__init__(action, middlewares)
    
    def check(self, request):
        self.apply_middlewares(request)
        return not request.is_secure
    
    def get_violation_message(self):
        return "Request must be made over HTTPS"

class RestrictedPathRule(FirewallRule):
    """Rule to restrict access to certain paths based on IP."""
    
    def __init__(self, paths, allowed_ips=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.paths = set(paths or [])
        self.allowed_ips = set(allowed_ips or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        if request.path in self.paths:
            if self.allowed_ips:
                client_ip = request.remote_addr
                if client_ip not in self.allowed_ips:
                    return True
            else:
                return True
        return False
    
    def get_violation_message(self):
        return f"Access to {request.path} is restricted"

class ParameterValidationRule(FirewallRule):
    """Rule to validate specific parameters in the request."""
    
    def __init__(self, param_validators, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.param_validators = param_validators
    
    def check(self, request):
        self.apply_middlewares(request)
        for param, validator in self.param_validators.items():
            value = request.args.get(param) or request.form.get(param)
            if value is None or not validator(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Invalid or missing parameters"

class HeaderValidationRule(FirewallRule):
    """Rule to validate specific headers in the request."""
    
    def __init__(self, header_validators, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.header_validators = header_validators
    
    def check(self, request):
        self.apply_middlewares(request)
        for header, validator in self.header_validators.items():
            value = request.headers.get(header)
            if value is None or not validator(value):
                return True
        return False
    
    def get_violation_message(self):
        return "Invalid or missing headers"

class MethodPathRule(FirewallRule):
    """Rule to specify allowed HTTP methods for certain paths."""
    
    def __init__(self, method_path_map, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.method_path_map = method_path_map
    
    def check(self, request):
        self.apply_middlewares(request)
        allowed_methods = self.method_path_map.get(request.path)
        if allowed_methods and request.method not in allowed_methods:
            return True
        return False
    
    def get_violation_message(self):
        return f"Method {request.method} not allowed for path {request.path}"

class RecaptchaRule(FirewallRule):
    """Rule to require reCAPTCHA verification."""
    
    def __init__(self, firewall, exempt_routes=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.firewall = firewall
        self.exempt_routes = exempt_routes or []
        self.verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    
    def check(self, request):
        self.apply_middlewares(request)
        # Skip if no secret key is set
        if not self.firewall.recaptcha_secret_key:
            return False
        
        # Skip if route is exempt
        for route in self.exempt_routes:
            if isinstance(route, str) and request.path == route:
                return False
            elif hasattr(route, 'match') and route.match(request.path):
                return False
        
        # Get reCAPTCHA token from JSON or form data
        recaptcha_response = None
        if request.is_json:
            recaptcha_response = request.json.get('recaptcha_token')
        else:
            recaptcha_response = request.form.get('recaptcha_token')
        
        if not recaptcha_response:
            return True
        
        # Verify reCAPTCHA
        try:
            data = {
                'secret': self.firewall.recaptcha_secret_key,
                'response': recaptcha_response
            }
            response = requests.post(self.verify_url, data=data, timeout=5)
            result = response.json()
            return not result.get('success', False)
        except Exception as e:
            current_app.logger.error(f"reCAPTCHA verification failed: {str(e)}")
            return True
    
    def get_violation_message(self):
        return "reCAPTCHA verification failed"

class ProtocolVersionRule(FirewallRule):
    """Rule to restrict HTTP protocol versions."""
    
    def __init__(self, allowed_versions=None, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.allowed_versions = allowed_versions or ['HTTP/2.0']
    
    def check(self, request):
        self.apply_middlewares(request)
        protocol = request.environ.get('SERVER_PROTOCOL', '')
        return protocol not in self.allowed_versions
    
    def get_violation_message(self):
        return f"HTTP protocol version {request.environ.get('SERVER_PROTOCOL')} not allowed"

class HoneypotRule(FirewallRule):
    """Rule to detect bots via honeypot fields."""
    
    def __init__(self, honeypot_fields, action='block', middlewares=None):
        super().__init__(action, middlewares)
        self.honeypot_fields = set(honeypot_fields or [])
    
    def check(self, request):
        self.apply_middlewares(request)
        for field in self.honeypot_fields:
            if request.form.get(field) or request.args.get(field):
                return True
        return False
    
    def get_violation_message(self):
        return "Honeypot field detected, possible bot"

class Firewall:
    """Flask firewall middleware for filtering requests."""
    
    def __init__(self, app=None, recaptcha_secret_key=None):
        """
        Initialize the firewall.
        
        Args:
            app: Flask application instance
            recaptcha_secret_key: Google reCAPTCHA secret key for verification
        """
        self.rules = []
        self.error_handler = None
        self.bypass_key = None
        self.recaptcha_secret_key = recaptcha_secret_key
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize the firewall with a Flask application.
        
        Args:
            app: Flask application instance
        """
        app.before_request(self._check_request)
        
        @app.errorhandler(403)
        def handle_forbidden(e):
            if self.error_handler:
                return self.error_handler(e)
            return jsonify({"error": "Request blocked by firewall", "description": str(e)}), 403
    
    def set_bypass_key(self, key):
        """Set a secret key to bypass firewall rules (e.g., for testing)."""
        self.bypass_key = key
        return self
    
    def add_rule(self, rule):
        """
        Add a rule to the firewall.
        
        Args:
            rule: An instance of FirewallRule
        """
        if not isinstance(rule, FirewallRule):
            raise TypeError("Rule must be an instance of FirewallRule")
        self.rules.append(rule)
        return self
    
    def set_error_handler(self, handler):
        """
        Set a custom error handler for 403 responses.
        
        Args:
            handler: Function to handle 403 errors
        """
        self.error_handler = handler
        return self
    
    def _check_request(self):
        if self.bypass_key and request.headers.get('X-Firewall-Bypass') == self.bypass_key:
            current_app.logger.info("Firewall bypassed with valid key")
            return
        
        for rule in self.rules:
            if rule.check(request):
                log_data = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "client_ip": request.remote_addr,
                    "method": request.method,
                    "path": request.path,
                    "headers": dict(request.headers),
                    "query_params": dict(request.args),
                    "rule": rule.__class__.__name__,
                    "action": rule.action,
                    "message": rule.get_violation_message()
                }
                if rule.action == 'allow':
                    current_app.logger.info(json.dumps({**log_data, "status": "allowed"}))
                    return
                elif rule.action == 'block':
                    current_app.logger.warning(json.dumps({**log_data, "status": "blocked"}))
                    abort(403, description=rule.get_violation_message())
                elif rule.action == 'log':
                    current_app.logger.info(json.dumps({**log_data, "status": "logged"}))

    def protect(self, f=None, rules=None):
        """
        Decorator to protect routes with specific rules.
        
        Args:
            f: View function to decorate
            rules: List of FirewallRule instances
        """
        def decorator(view_func):
            @wraps(view_func)
            def wrapped(*args, **kwargs):
                if rules:
                    for rule in rules:
                        if rule.check(request):
                            log_data = {
                                "timestamp": datetime.utcnow().isoformat(),
                                "client_ip": request.remote_addr,
                                "method": request.method,
                                "path": request.path,
                                "headers": dict(request.headers),
                                "query_params": dict(request.args),
                                "rule": rule.__class__.__name__,
                                "action": rule.action,
                                "message": rule.get_violation_message()
                            }
                            if rule.action == 'block':
                                current_app.logger.warning(json.dumps({**log_data, "status": "blocked"}))
                                abort(403, description=rule.get_violation_message())
                            elif rule.action == 'log':
                                current_app.logger.info(json.dumps({**log_data, "status": "logged"}))
                return view_func(*args, **kwargs)
            return wrapped
        if f:
            return decorator(f)
        return decorator
    
    # Convenience methods
    def all_ip_allow(self):
        """Allow all IP addresses."""
        return self.add_rule(IPRule(['0.0.0.0/0', '::/0'], action='allow'))
    
    def block_ips(self, ip_list, middlewares=None):
        """Block specific IPs."""
        return self.add_rule(IPRule(ip_list, action='block', middlewares=middlewares))
    
    def allow_ips(self, ip_list, middlewares=None):
        """Allow specific IPs."""
        return self.add_rule(IPRule(ip_list, action='allow', middlewares=middlewares))
    
    def rate_limit(self, limit=100, period=60, middlewares=None):
        """Limit requests per IP."""
        return self.add_rule(RateLimitRule(limit, period, middlewares=middlewares))
    
    def session_rate_limit(self, limit=50, period=60, session_key_header='X-Session-Token', middlewares=None):
        """Limit requests per session token."""
        return self.add_rule(SessionRateLimitRule(limit, period, session_key_header, middlewares=middlewares))
    
    def protect_from_xss(self, middlewares=None):
        """Block XSS attempts."""
        return self.add_rule(XSSRule(middlewares=middlewares))
    
    def protect_from_sql_injection(self, middlewares=None):
        """Block SQL injection attempts."""
        return self.add_rule(SQLInjectionRule(middlewares=middlewares))
    
    def protect_from_path_traversal(self, middlewares=None):
        """Block path traversal attacks."""
        return self.add_rule(PathTraversalRule(middlewares=middlewares))
    
    def csrf_protection(self, exempt_routes=None, middlewares=None):
        """Enforce CSRF token validation."""
        return self.add_rule(CSRFProtectionRule(exempt_routes, middlewares=middlewares))
    
    def restrict_methods(self, allowed_methods=None, middlewares=None):
        """Restrict HTTP methods."""
        return self.add_rule(MethodRule(allowed_methods, middlewares=middlewares))
    
    def restrict_referrers(self, allowed_domains=None, middlewares=None):
        """Restrict referrers."""
        return self.add_rule(ReferrerRule(allowed_domains, middlewares=middlewares))
    
    def restrict_content_types(self, allowed_types=None, middlewares=None):
        """Restrict content types."""
        return self.add_rule(ContentTypeRule(allowed_types, middlewares=middlewares))
    
    def allow_user_agent(self, user_agents, middlewares=None):
        """Allow specific user agents."""
        return self.add_rule(UserAgentRule(user_agents, action='allow', middlewares=middlewares))
    
    def block_user_agent(self, user_agents, middlewares=None):
        """Block specific user agents."""
        return self.add_rule(UserAgentRule(user_agents, action='block', middlewares=middlewares))
    
    def limit_request_size(self, max_size=1024*1024, middlewares=None):
        """Limit request size."""
        return self.add_rule(RequestSizeRule(max_size=max_size, middlewares=middlewares))
    
    def restrict_origins(self, origins, action='block', middlewares=None):
        """Restrict origins."""
        return self.add_rule(OriginRule(origins, action=action, middlewares=middlewares))
    
    def forbid_headers(self, forbidden_headers, middlewares=None):
        """Forbid specific headers."""
        return self.add_rule(HeaderRule(forbidden_headers, middlewares=middlewares))
    
    def restrict_hosts(self, hosts, action='block', middlewares=None):
        """Restrict hosts."""
        return self.add_rule(HostRule(hosts, action=action, middlewares=middlewares))
    
    def validate_json_body(self, required_fields=None, max_depth=5, middlewares=None):
        """Validate JSON request bodies."""
        return self.add_rule(RequestBodyRule(required_fields, max_depth, middlewares=middlewares))
    
    def restrict_time(self, start_hour, end_hour, timezone='UTC', middlewares=None):
        """Restrict access by time."""
        return self.add_rule(TimeBasedRule(start_hour, end_hour, timezone, middlewares=middlewares))
    
    def custom_regex(self, patterns, middlewares=None):
        """Match custom regex patterns."""
        return self.add_rule(CustomRegexRule(patterns, middlewares=middlewares))
    
    def protect_from_command_injection(self, middlewares=None):
        """Block command injection attempts."""
        return self.add_rule(CommandInjectionRule(middlewares=middlewares))
    
    def require_api_key(self, validate_func, header='X-API-Key', middlewares=None):
        """Require valid API keys."""
        return self.add_rule(APIKeyRule(validate_func, header, middlewares=middlewares))
    
    def enforce_https(self, middlewares=None):
        """Enforce HTTPS."""
        return self.add_rule(SecureConnectionRule(middlewares=middlewares))
    
    def restrict_paths(self, paths, allowed_ips=None, middlewares=None):
        """Restrict paths by IP."""
        return self.add_rule(RestrictedPathRule(paths, allowed_ips, middlewares=middlewares))
    
    def validate_parameters(self, param_validators, middlewares=None):
        """Validate parameters."""
        return self.add_rule(ParameterValidationRule(param_validators, middlewares=middlewares))
    
    def validate_headers(self, header_validators, middlewares=None):
        """Validate headers."""
        return self.add_rule(HeaderValidationRule(header_validators, middlewares=middlewares))
    
    def restrict_methods_for_paths(self, method_path_map, middlewares=None):
        """Restrict methods per path."""
        return self.add_rule(MethodPathRule(method_path_map, middlewares=middlewares))
    
    def recaptcha(self, exempt_routes=None, middlewares=None):
        """Require reCAPTCHA verification using the stored secret key."""
        return self.add_rule(RecaptchaRule(self, exempt_routes, middlewares=middlewares))
    
    def restrict_protocol(self, allowed_versions=None, middlewares=None):
        """Restrict HTTP protocol versions."""
        return self.add_rule(ProtocolVersionRule(allowed_versions, middlewares=middlewares))
    
    def add_honeypot(self, honeypot_fields, middlewares=None):
        """Detect bots via honeypot fields."""
        return self.add_rule(HoneypotRule(honeypot_fields, middlewares=middlewares))