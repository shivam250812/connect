"""Settings read from the environment (all optional). Paths are relative to where the app is started."""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).parent
STATIC = PACKAGE_DIR / "web" / "static"
LAB = os.environ.get("CF_LAB") == "1"  # mock lab sources, for failure drills
_DEFAULT_DIRS = ("integrations/connectors:integrations/lab:integrations/lab/enterprise" if LAB
                 else "integrations/connectors")
# the first directory is where connectors added in the UI are saved
DIRS = [Path(d) for d in os.environ.get("CF_CONNECTORS_DIRS", _DEFAULT_DIRS).split(":") if d]
DATA_DIR = Path(os.environ.get("CF_DATA_DIR", "data"))
EXAMPLE_DIRS = [Path("integrations/examples"), Path("integrations/catalog"), Path("integrations/connectors")] + \
    ([Path("integrations/lab")] if LAB else [])
