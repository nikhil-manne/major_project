"""
Labs Service Package
Provides persistent Lab definitions, Dockerfile/compose file uploads,
and multi-session concurrency management.
"""
from .service import router as labs_router

__all__ = ["labs_router"]
