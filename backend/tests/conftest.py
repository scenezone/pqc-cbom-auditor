import pytest
import pathlib

@pytest.fixture(scope="session")
def tmp_path_factory(request, tmp_path_factory):
    """Override tmp_path_factory to use a local directory, avoiding AppData permission issues."""
    return tmp_path_factory


def pytest_configure(config):
    """Redirect pytest temp directory to local .tmp folder to avoid Windows AppData permission issues."""
    local_tmp = pathlib.Path(__file__).parent.parent / ".tmp" / "pytest"
    local_tmp.mkdir(parents=True, exist_ok=True)
    config.option.basetemp = str(local_tmp)
