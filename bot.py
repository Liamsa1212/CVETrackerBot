"""CVETrackerBot execution shim for backward compatibility."""

import sys
from cve_tracker.main import main

if __name__ == "__main__":
    main()
