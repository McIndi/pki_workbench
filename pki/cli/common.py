from pathlib import Path


def print_response(status_code: int, body):
    import json

    print(f'HTTP {status_code}')
    if isinstance(body, dict):
        print(json.dumps(body, indent=2, sort_keys=True))
    else:
        print(body)


def raise_for_error(status_code: int, body):
    if status_code >= 400:
        raise SystemExit(f'API request failed (HTTP {status_code}): {body}')


def read_text_file(path_value: str, option_name: str) -> str:
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        raise SystemExit(f'{option_name} is not a readable file: {path}')
    return path.read_text(encoding='utf-8')


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def add_subject_args(parser, *, required: bool):
    parser.add_argument('--country-name', required=required)
    parser.add_argument('--state-or-province-name', required=required)
    parser.add_argument('--locality-name', required=required)
    parser.add_argument('--organization-name', required=required)
    parser.add_argument('--common-name', required=required)
    parser.add_argument('--organizational-unit-name', default='')
    parser.add_argument('--email-address', default='')


def add_keygen_args(parser):
    parser.add_argument('--key-algorithm', choices=['rsa', 'ec', 'eddsa'], default='rsa')
    parser.add_argument('--curve-name', default='secp256r1')
    parser.add_argument('--key-size', type=int, default=2048)
    parser.add_argument('--public-exponent', type=int, default=65537)
