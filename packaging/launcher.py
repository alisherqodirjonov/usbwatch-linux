#!/usr/bin/env python3
# Entry point installed next to the 'usbwatch' package. Python puts this script's folder first on
# sys.path, so the wrapper can run Python with -E -s (environment and user site ignored).
import sys

from usbwatch.cli import main

sys.exit(main())
