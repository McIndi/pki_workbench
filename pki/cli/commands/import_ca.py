from ..common import print_response, raise_for_error, read_text_file


def register(subparsers):
    parser = subparsers.add_parser('import-ca', help='Import CA cert+key')
    parser.add_argument('--name', required=True)
    parser.add_argument('--certificate-pem-file', required=True)
    parser.add_argument('--private-key-pem-file', required=True)
    parser.add_argument('--key-passphrase', default='')
    parser.add_argument('--parent-ca-id', type=int)
    parser.add_argument('--certification-depth', type=int, default=3)
    parser.set_defaults(func=run)


def run(client, args):
    payload = {
        'name': args.name,
        'certificate_pem': read_text_file(args.certificate_pem_file, '--certificate-pem-file'),
        'private_key_pem': read_text_file(args.private_key_pem_file, '--private-key-pem-file'),
        'key_passphrase': args.key_passphrase,
        'parent_ca_id': args.parent_ca_id,
        'certification_depth': args.certification_depth,
    }
    status, body = client.request('POST', 'workflows/import-ca/', payload)
    print_response(status, body)
    raise_for_error(status, body)
