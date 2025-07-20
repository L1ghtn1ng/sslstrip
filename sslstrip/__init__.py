"""sslstrip package."""

import os
import sys

# Add the parent directory to the path so we can import the main sslstrip module
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from sslstrip import main
except ImportError:
    # Fallback: try importing from the module file directly
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        'sslstrip_main', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sslstrip.py')
    )
    sslstrip_main = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sslstrip_main)
    main = sslstrip_main.main

__all__ = ['main']
