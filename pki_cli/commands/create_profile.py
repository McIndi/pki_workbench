from ..common import add_keygen_args, add_subject_args, print_response, raise_for_error


def register(subparsers):
    parser = subparsers.add_parser('create-profile', help='Create certificate profile')
    parser.add_argument('--name', required=True)
    parser.add_argument('--description', default='')
    parser.add_argument('--is-ca', action='store_true')
    parser.add_argument('--path-length', type=int)
    parser.add_argument('--days-valid', type=int, default=365)
    add_keygen_args(parser)
    add_subject_args(parser, required=False)
    parser.set_defaults(func=run)


def run(client, args):
    payload = {
        'name': args.name,
        'description': args.description,
        'is_ca': args.is_ca,
        'path_length': args.path_length,
        'days_valid': args.days_valid,
        'key_algorithm': args.key_algorithm,
        'curve_name': args.curve_name,
        'key_size': args.key_size,
        'public_exponent': args.public_exponent,
        'country_name': args.country_name,
        'state_or_province_name': args.state_or_province_name,
        'locality_name': args.locality_name,
        'organization_name': args.organization_name,
        'organizational_unit_name': args.organizational_unit_name,
        'common_name': args.common_name,
        'email_address': args.email_address,
    }
    status, body = client.request('POST', 'profiles/', payload)
    print_response(status, body)
    raise_for_error(status, body)
