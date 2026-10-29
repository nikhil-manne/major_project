"""
Cyber Range Shared Library
Defines normalized schemas, configuration, and data structures.
"""
from .schema import NormalizedEvent, SourceType, Severity, Outcome
from .config import settings

__all__ = ["NormalizedEvent", "SourceType", "Severity", "Outcome", "settings"]
