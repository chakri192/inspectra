import pytest
from app.main import _rate_limit_records


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure test runs do not inadvertently exhaust the 60 req/min limit across test cases."""
    _rate_limit_records.clear()
    yield
    _rate_limit_records.clear()
