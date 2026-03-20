import argparse
import os

from .client import APIClient
from .commands import (
    create_intermediate_ca,
    create_profile,
    create_root_ca,
    delete_resource,
    derive_profile,
    import_ca,
    issue_certificate,
)

DEFAULT_BASE_URL = 'http://localhost:8000/api/'


def build_parser():
    parser = argparse.ArgumentParser(description='PKI Workbench REST API CLI wrapper')
    parser.add_argument('--base-url', default=os.getenv('PKI_API_BASE_URL', DEFAULT_BASE_URL))
    parser.add_argument('--username', default=os.getenv('PKI_API_USERNAME'))
    parser.add_argument('--password', default=os.getenv('PKI_API_PASSWORD'))
    parser.add_argument('--timeout', type=float, default=float(os.getenv('PKI_API_TIMEOUT', '30')))

    subparsers = parser.add_subparsers(dest='command', required=True)
    create_root_ca.register(subparsers)
    create_intermediate_ca.register(subparsers)
    import_ca.register(subparsers)
    issue_certificate.register(subparsers)
    create_profile.register(subparsers)
    derive_profile.register(subparsers)
    delete_resource.register(subparsers)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        client = APIClient(
            base_url=args.base_url,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    args.func(client, args)
