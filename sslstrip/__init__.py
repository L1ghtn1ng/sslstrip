"""sslstrip package."""

import importlib.util
import os
from typing import Any

# Import the main function from the sslstrip.py module file directly
spec = importlib.util.spec_from_file_location(
    'sslstrip_main', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sslstrip.py')
)

if spec is None or spec.loader is None:
    raise ImportError('Could not load sslstrip module')

sslstrip_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sslstrip_main)
main: Any = sslstrip_main.main

__all__ = ['main']
