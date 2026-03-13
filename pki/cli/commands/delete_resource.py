from ..common import print_response, raise_for_error


DELETE_PATHS = {
    'certificate': ('workflows/delete-certificate/', 'certificate_id'),
    'ca': ('workflows/delete-ca/', 'target_ca_id'),
    'private-key': ('workflows/delete-private-key/', 'private_key_id'),
    'csr': ('workflows/delete-csr/', 'csr_id'),
}


def register(subparsers):
    parser = subparsers.add_parser('delete-resource', help='Delete CA/certificate/private-key/csr')
    parser.add_argument('--resource-type', choices=sorted(DELETE_PATHS.keys()), required=True)
    parser.add_argument('--resource-id', type=int, required=True)
    parser.set_defaults(func=run)


def run(client, args):
    path, payload_key = DELETE_PATHS[args.resource_type]
    status, body = client.request('POST', path, {payload_key: args.resource_id})
    print_response(status, body)
    raise_for_error(status, body)
