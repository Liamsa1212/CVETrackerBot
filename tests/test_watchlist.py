"""Tests for WatchlistParser dependency manifest extraction."""

from cve_tracker.services.watchlist import WatchlistParser


def test_parse_requirements_txt():
    sample_requirements = """
    # Production dependencies
    fastapi>=0.110.0,<1.0.0
    uvicorn[standard]==0.29.0
    pydantic==2.7.0
    sqlalchemy>=2.0.30

    # Development & test
    --extra-index-url https://example.com/pypi
    pytest>=8.0.0 # testing
    httpx==0.27.0
    """

    packages = WatchlistParser.parse_requirements_txt(sample_requirements)
    assert "fastapi" in packages
    assert "uvicorn" in packages
    assert "pydantic" in packages
    assert "sqlalchemy" in packages
    assert "pytest" in packages
    assert "httpx" in packages
    assert len(packages) == 6


def test_parse_package_json():
    sample_pkg = """
    {
      "name": "sample-app",
      "version": "1.0.0",
      "dependencies": {
        "react": "^18.2.0",
        "react-dom": "^18.2.0",
        "axios": "^1.6.8",
        "@types/node": "^20.0.0"
      },
      "devDependencies": {
        "typescript": "^5.4.5",
        "vite": "^5.2.0"
      }
    }
    """

    packages = WatchlistParser.parse_package_json(sample_pkg)
    assert "react" in packages
    assert "react-dom" in packages
    assert "axios" in packages
    assert "typescript" in packages
    assert "vite" in packages
    assert "node" in packages


def test_parse_comma_separated():
    raw_input = "nginx, postgresql; redis\ndocker kubernetes"
    items = WatchlistParser.parse_comma_separated(raw_input)
    assert items == ["docker", "kubernetes", "nginx", "postgresql", "redis"]
