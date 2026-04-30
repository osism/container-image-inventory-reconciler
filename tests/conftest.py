# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures and path setup for unit tests.

The Python sources under ``files/netbox/`` are not packaged. They are copied
into the container image at ``/netbox/`` and run as scripts (``python main.py``).
Imports inside the package are unqualified (``from utils import ...``,
``from config import ...``), so we add ``files/netbox/`` to ``sys.path`` here
to mirror the runtime layout.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_NETBOX_SRC = _REPO_ROOT / "files" / "netbox"

if str(_NETBOX_SRC) not in sys.path:
    sys.path.insert(0, str(_NETBOX_SRC))
