"""Defensive password auditing and authentication-event detection."""

from .audit import audit_password
from .detector import AuthEventDetector, DetectionConfig

__all__ = ["AuthEventDetector", "DetectionConfig", "audit_password"]
__version__ = "1.0.0"
