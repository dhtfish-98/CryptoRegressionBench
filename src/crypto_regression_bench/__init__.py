"""Actual bounded AES-GCM regression; never a whole-library security verdict."""
from .runner import run_vectors
from .schema import Limits
__version__ = '0.1.2'
__all__ = ['Limits', 'run_vectors']
