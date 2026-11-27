"""`python3 -m software.scout`, which is what the unit runs."""

import sys

from .scout import main

if __name__ == "__main__":
    sys.exit(main())
