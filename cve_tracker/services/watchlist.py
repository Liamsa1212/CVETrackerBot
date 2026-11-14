"""Dependency manifest and tech stack watchlist parser."""

import json
import re
from typing import List, Set
from loguru import logger


class WatchlistParser:
    """Parses software dependency manifests and package lists into normalized package names."""

    @staticmethod
    def parse_requirements_txt(content: str) -> List[str]:
        """Parse standard Python requirements.txt file."""
        packages: Set[str] = set()
        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Ignore empty lines, comments, and flags
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Strip inline comments
            line = line.split("#")[0].strip()

            # Regex for package name (PEP 508): alphanumeric, underscore, dot, dash
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
            if match:
                pkg_name = match.group(1).lower().strip()
                if pkg_name:
                    packages.add(pkg_name)

        return sorted(list(packages))

    @staticmethod
    def parse_package_json(content: str) -> List[str]:
        """Parse JavaScript package.json dependencies."""
        packages: Set[str] = set()
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for dep_section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    deps = data.get(dep_section, {})
                    if isinstance(deps, dict):
                        for pkg in deps.keys():
                            clean_pkg = pkg.lower().strip()
                            # Handle scoped packages e.g. @angular/core -> angular, core
                            if clean_pkg.startswith("@") and "/" in clean_pkg:
                                parts = clean_pkg[1:].split("/")
                                packages.add(parts[0])
                                packages.add(parts[1])
                            else:
                                packages.add(clean_pkg)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse package.json: {e}")

        return sorted(list(packages))

    @classmethod
    def parse_manifest(cls, filename: str, content: str) -> List[str]:
        """Detect and parse dependency file based on filename."""
        fn_lower = filename.lower()
        if "package.json" in fn_lower:
            return cls.parse_package_json(content)
        elif "requirements" in fn_lower or fn_lower.endswith(".txt"):
            return cls.parse_requirements_txt(content)
        elif fn_lower.endswith(".json"):
            # Try parsing as package.json first
            parsed = cls.parse_package_json(content)
            if parsed:
                return parsed
        # Fallback to lines
        return cls.parse_requirements_txt(content)

    @staticmethod
    def parse_comma_separated(text: str) -> List[str]:
        """Parse comma or space separated list of software names."""
        items: Set[str] = set()
        # Replace commas, semicolons, and newlines with spaces
        normalized = text.replace(",", " ").replace(";", " ").replace("\n", " ")
        for token in normalized.split():
            clean = token.strip().lower()
            # Remove leading/trailing non-alphanumeric
            clean = re.sub(r"^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$", "", clean)
            if clean and len(clean) >= 2:
                items.add(clean)

        return sorted(list(items))
