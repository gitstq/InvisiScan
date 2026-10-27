"""Allow ``python -m invisiscan``."""

import sys

from .cli import force_utf8_stdio, main

if __name__ == "__main__":
    force_utf8_stdio()
    sys.exit(main())
