from ..common import print_response, raise_for_error


def register(subparsers):
    parser = subparsers.add_parser('derive-profile', help='Derive profile from certificate')
    parser.add_argument('--certificate-id', type=int, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--description', default='')
    parser.set_defaults(func=run)


def run(client, args):
    payload = {
        'certificate_id': args.certificate_id,
        'name': args.name,
        'description': args.description,
    }
    status, body = client.request('POST', 'workflows/profiles/from-certificate/', payload)
    print_response(status, body)
    raise_for_error(status, body)
