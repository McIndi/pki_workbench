from ..common import add_keygen_args, add_subject_args, print_response, raise_for_error


def register(subparsers):
    parser = subparsers.add_parser('create-root-ca', help='Create root CA')
    parser.add_argument('--name', required=True)
    add_subject_args(parser, required=True)
    parser.add_argument('--certification-depth', type=int, default=3)
    parser.add_argument('--days-valid', type=int, default=3650)
    add_keygen_args(parser)
    parser.add_argument('--passphrase', default='')
    parser.set_defaults(func=run)


def run(client, args):
    payload = {
        'name': args.name,
        'country_name': args.country_name,
        'state_or_province_name': args.state_or_province_name,
        'locality_name': args.locality_name,
        'organization_name': args.organization_name,
        'common_name': args.common_name,
        'email_address': args.email_address,
        'certification_depth': args.certification_depth,
        'days_valid': args.days_valid,
        'key_algorithm': args.key_algorithm,
        'curve_name': args.curve_name,
        'key_size': args.key_size,
        'public_exponent': args.public_exponent,
        'passphrase': args.passphrase,
    }
    status, body = client.request('POST', 'workflows/root-cas/', payload)
    print_response(status, body)
    raise_for_error(status, body)
