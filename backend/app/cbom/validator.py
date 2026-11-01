import json
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from app.config import get_settings

class CBOMValidationError(Exception):
    pass

class CBOMValidator:
    def __init__(self):
        self._validator = None

    def _load(self):
        if self._validator:
            return self._validator
        path = get_settings().cyclonedx_schema_path
        if not path.exists():
            raise CBOMValidationError(f"CycloneDX schema not found at {path}. Download the official CycloneDX 1.7 JSON schema before validation.")
        with path.open(encoding="utf-8") as h:
            schema = json.load(h)
        try:
            v = Draft202012Validator(schema, format_checker=FormatChecker())
            v.check_schema(schema)
        except SchemaError as exc:
            raise CBOMValidationError("Invalid CycloneDX schema") from exc
        self._validator = v
        return v

    def validate(self, cbom):
        if isinstance(cbom, (str,)):
            cbom = json.loads(cbom)
        v = self._load()
        errors = sorted(v.iter_errors(cbom), key=lambda e: list(e.absolute_path))
        return {"valid": len(errors) == 0, "schema": "CycloneDX 1.7",
                "errors": [{"path": ".".join(str(p) for p in e.absolute_path) or "$",
                            "message": e.message} for e in errors]}
