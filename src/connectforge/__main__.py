"""`python -m connectforge ...` runs the command line tool."""

import sys

from connectforge.cli import main

sys.exit(main(sys.argv[1:]))
