from ..common import add_keygen_args, add_subject_args, print_response, raise_for_error, read_text_file
from ..csr import generate_csr_from_args


def register(subparsers):
    parser = subparsers.add_parser('issue-certificate', help='Issue cert (generate or BYOK CSR)')
    parser.add_argument('--issuer-ca-id', type=int, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--certificate-profile-id', type=int)
    parser.add_argument('--mode', choices=['generate', 'csr'], default='generate')
    parser.add_argument('--days-valid', type=int, default=365)
    parser.add_argument('--issuer-key-passphrase', default='')

    add_subject_args(parser, required=False)
    add_keygen_args(parser)
    parser.add_argument('--passphrase', default='')
    parser.add_argument('--san-dns-names', default='')

    parser.add_argument('--csr-pem-file')
    parser.add_argument('--generate-csr', action='store_true')
    parser.add_argument('--save-generated-key-file')
    parser.add_argument('--save-generated-csr-file')

    parser.add_argument('--csr-key-algorithm', choices=['rsa', 'ec', 'eddsa'], default='rsa')
    parser.add_argument('--csr-curve-name', default='secp256r1')
    parser.add_argument('--csr-key-size', type=int, default=2048)
    parser.add_argument('--csr-public-exponent', type=int, default=65537)
    parser.add_argument('--csr-key-passphrase', default='')
    parser.add_argument('--csr-san-dns-names', default='')

    parser.set_defaults(func=run)


def run(client, args):
    if args.mode == 'generate':
        payload = {
            'issuer_ca_id': args.issuer_ca_id,
            'name': args.name,
            'certificate_profile_id': args.certificate_profile_id,
            'country_name': args.country_name,
            'state_or_province_name': args.state_or_province_name,
            'locality_name': args.locality_name,
            'organization_name': args.organization_name,
            'organizational_unit_name': args.organizational_unit_name,
            'common_name': args.common_name,
            'email_address': args.email_address,
            'days_valid': args.days_valid,
            'key_algorithm': args.key_algorithm,
            'curve_name': args.curve_name,
            'key_size': args.key_size,
            'public_exponent': args.public_exponent,
            'passphrase': args.passphrase,
            'issuer_key_passphrase': args.issuer_key_passphrase,
            'san_dns_names': args.san_dns_names,
        }
        status, body = client.request('POST', 'workflows/certificates/', payload)
    else:
        if args.generate_csr:
            csr_pem = generate_csr_from_args(args)
        elif args.csr_pem_file:
            csr_pem = read_text_file(args.csr_pem_file, '--csr-pem-file')
        else:
            raise SystemExit('For --mode csr, provide --csr-pem-file or --generate-csr.')

        payload = {
            'name': args.name,
            'certificate_profile_id': args.certificate_profile_id,
            'csr_pem': csr_pem,
            'issuer_key_passphrase': args.issuer_key_passphrase,
            'days_valid': args.days_valid,
        }
        status, body = client.request('POST', f'cas/{args.issuer_ca_id}/sign-csr/', payload)

    print_response(status, body)
    raise_for_error(status, body)
