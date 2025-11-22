import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError
import os

def validate_login(request):
    schema_path = os.path.join(os.path.dirname(__file__), "../api_schemas/login_schema.json")

    with open(schema_path) as f:
        schema = json.load(f)

    try:
        validate(instance=request.get_json(), schema=schema)
        return request.get_json()
    except ValidationError as e:
        return f"error: {e}"