"""Pytest config: ensure the test_org_id_helpers module can import 'app'."""
import sys
from pathlib import Path

# Add services/ to sys.path so `from app.middleware import ...` works
services_dir = Path(__file__).resolve().parent.parent / "services"
sys.path.insert(0, str(services_dir))

# Add tests/ to sys.path so `from tests.test_org_id_helpers import ...` works
tests_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(tests_dir))
