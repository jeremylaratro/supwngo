#!/usr/bin/env python3
"""
SupwnGo - Automated Binary Exploitation Framework

Central run script that allows running without installation.
Usage:
    ./supwngo.py [command] [options]
    python supwngo.py [command] [options]

For installation:
    pip install -e .
    # Then use: supwngo [command] [options]
"""

import sys
from pathlib import Path

# Add the project root to Python path for direct execution
project_root = Path(__file__).parent.resolve()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from supwngo.cli import main

if __name__ == "__main__":
    main()
