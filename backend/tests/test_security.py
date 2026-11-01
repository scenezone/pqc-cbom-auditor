import zipfile
import pytest
from app.scanner.repository_loader import RepositoryValidationError, extract_zip

def test_rejects_traversal(tmp_path):
    a = tmp_path / "m.zip"
    with zipfile.ZipFile(a, "w") as zf:
        zf.writestr("../../evil.txt", "x")
    w = tmp_path / "w"; w.mkdir()
    with pytest.raises(RepositoryValidationError):
        extract_zip(a, w)
