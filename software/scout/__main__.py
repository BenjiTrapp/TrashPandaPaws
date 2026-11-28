"""`python3 -m software.scout`, which is what the unit runs."""

import os
import sys

from .scout import main

if __name__ == "__main__":
    # Owner-only, before anything this process writes. See the longer note
    # in software/c2/server.py; in the guard rather than in main() so that
    # calling main() from a test does not change the test process.
    os.umask(0o077)
    sys.exit(main())
