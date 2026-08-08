"""Generate the REST API reference during an MkDocs build.

Reuses Django REST Framework's own built-in schema generator (the same one
`rest_framework.schemas.get_schema_view` uses at `/api/schema/`) rather than
reimplementing OpenAPI generation, then renders the schema as plain Markdown
instead of embedding an interactive widget.
"""

import json
import os
import sys
from pathlib import Path
from textwrap import dedent

import django
import mkdocs_gen_files


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from rest_framework.schemas.openapi import SchemaGenerator  # noqa: E402

METHOD_ORDER = ["get", "post", "put", "patch", "delete"]


def build_schema() -> dict:
    """Build the OpenAPI schema in-process, the same way `/api/schema/` does."""
    generator = SchemaGenerator(
        title="PKI Workbench API",
        description="REST API for PKI Workbench certificate authority and issuance workflows.",
        version="1.0.0",
    )
    return generator.get_schema(request=None, public=True)


def resolve(schema_or_ref: dict, components: dict) -> dict:
    """Follow a single `$ref` into `components.schemas`, if present."""
    if "$ref" in schema_or_ref:
        name = schema_or_ref["$ref"].rsplit("/", 1)[-1]
        return components.get("schemas", {}).get(name, {})
    return schema_or_ref


def type_label(prop: dict) -> str:
    """Render a short, human-readable type for one schema property."""
    if "$ref" in prop:
        return prop["$ref"].rsplit("/", 1)[-1]
    prop_type = prop.get("type", "any")
    if prop_type == "array":
        return f"array of {type_label(prop.get('items', {}))}"
    if fmt := prop.get("format"):
        return f"{prop_type} ({fmt})"
    return prop_type


def properties_table(schema: dict, components: dict, direction: str) -> list[str]:
    """Render a schema's object properties as a Markdown table."""
    schema = resolve(schema, components)
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))

    rows: list[tuple[str, str, str, str]] = []
    for name, prop in properties.items():
        if direction == "request" and prop.get("readOnly"):
            continue
        if direction == "response" and prop.get("writeOnly"):
            continue
        rows.append(
            (
                name,
                type_label(prop),
                "yes" if name in required else "no",
                (prop.get("description") or "").replace("\n", " ").strip() or "-",
            )
        )

    if not rows:
        return []

    lines = ["| Field | Type | Required | Description |", "| --- | --- | --- | --- |"]
    for name, type_str, required_str, description in rows:
        lines.append(f"| `{name}` | `{type_str}` | {required_str} | {description} |")
    lines.append("")
    return lines


def parameters_table(parameters: list[dict]) -> list[str]:
    """Render operation parameters as a Markdown table."""
    if not parameters:
        return []
    lines = ["| Parameter | Location | Type | Required | Description |", "| --- | --- | --- | --- | --- |"]
    for param in parameters:
        schema = param.get("schema", {})
        lines.append(
            f"| `{param['name']}` | {param.get('in', '-')} | `{type_label(schema)}` | "
            f"{'yes' if param.get('required') else 'no'} | "
            f"{(param.get('description') or '-').replace(chr(10), ' ')} |"
        )
    lines.append("")
    return lines


def security_line(operation: dict) -> str:
    schemes = {name for requirement in operation.get("security", []) for name in requirement}
    if not schemes:
        return "None"
    return ", ".join(sorted(schemes))


def render_operation(method: str, path: str, operation: dict, components: dict) -> list[str]:
    lines = [f"### `{method.upper()} {path}`", ""]

    summary = (operation.get("summary") or "").strip()
    description = (operation.get("description") or "").strip()
    if summary:
        lines += [f"**Summary:** {summary}", ""]
    if description:
        lines += [description, ""]

    lines += [f"**Authentication:** {security_line(operation)}", ""]
    lines += parameters_table(operation.get("parameters", []))

    request_body = operation.get("requestBody")
    if request_body:
        content = request_body.get("content", {})
        schema = next(iter(content.values()), {}).get("schema") if content else None
        lines.append("**Request body**")
        lines.append("")
        if schema:
            table = properties_table(schema, components, "request")
            lines += table if table else ["No documented fields.", ""]
        else:
            lines += ["No request body schema.", ""]

    for status in sorted(operation.get("responses", {}).keys()):
        response = operation["responses"][status]
        content = response.get("content", {})
        schema = next(iter(content.values()), {}).get("schema") if content else None
        lines.append(f"**Response `{status}`**")
        lines.append("")
        if not schema:
            lines += ["No response body.", ""]
            continue

        resolved = resolve(schema, components)
        if resolved.get("type") == "array":
            lines += ["Array of:", ""]
            table = properties_table(resolved.get("items", {}), components, "response")
            lines += table if table else ["No documented fields.", ""]
            continue

        table = properties_table(schema, components, "response")
        lines += table if table else ["No documented fields.", ""]

    return lines


schema = build_schema()

with mkdocs_gen_files.open("reference/openapi.json", "w") as output:
    output.write(json.dumps(schema, indent=2, sort_keys=True))

with mkdocs_gen_files.open("reference/rest-api.md", "w") as output:
    info = schema.get("info", {})
    output.write(
        dedent(
            f"""\
            ---
            title: REST API
            ---

            # REST API

            {info.get('description', '')}

            This reference is generated from the running Django app's route
            definitions and DRF's `AutoSchema` introspection, the same
            generator that serves `/api/schema/` on a live instance.

            The raw schema is available at [openapi.json](openapi.json).

            """
        )
    )

    components = schema.get("components", {})
    paths = schema.get("paths", {})
    for path in sorted(paths):
        operations = paths[path]
        for method in METHOD_ORDER:
            if method not in operations:
                continue
            output.write("\n".join(render_operation(method, path, operations[method], components)))
            output.write("\n")
