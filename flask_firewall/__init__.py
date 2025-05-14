
"""
Flask-Firewall: A comprehensive firewall middleware for Flask applications.
Provides rules for IP filtering, rate limiting, reCAPTCHA, XSS protection, and more.
"""

__version__ = "0.1.0"

from .firewall import Firewall, FirewallRule, FirewallException
from .firewall import (
    IPRule, RateLimitRule, SessionRateLimitRule, XSSRule, SQLInjectionRule,
    PathTraversalRule, CSRFProtectionRule, MethodRule, ReferrerRule,
    ContentTypeRule, UserAgentRule, RequestSizeRule, OriginRule, HeaderRule,
    HostRule, RequestBodyRule, TimeBasedRule, CustomRegexRule,
    CommandInjectionRule, APIKeyRule, SecureConnectionRule, RestrictedPathRule,
    ParameterValidationRule, HeaderValidationRule, MethodPathRule,
    RecaptchaRule, ProtocolVersionRule, HoneypotRule
)

__all__ = [
    'Firewall', 'FirewallRule', 'FirewallException',
    'IPRule', 'RateLimitRule', 'SessionRateLimitRule', 'XSSRule', 'SQLInjectionRule',
    'PathTraversalRule', 'CSRFProtectionRule', 'MethodRule', 'ReferrerRule',
    'ContentTypeRule', 'UserAgentRule', 'RequestSizeRule', 'OriginRule', 'HeaderRule',
    'HostRule', 'RequestBodyRule', 'TimeBasedRule', 'CustomRegexRule',
    'CommandInjectionRule', 'APIKeyRule', 'SecureConnectionRule', 'RestrictedPathRule',
    'ParameterValidationRule', 'HeaderValidationRule', 'MethodPathRule',
    'RecaptchaRule', 'ProtocolVersionRule', 'HoneypotRule'
]