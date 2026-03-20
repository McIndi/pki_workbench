from unittest import TestCase
from unittest.mock import patch

from pki_cli.client import APIClient
from pki_cli.main import build_parser


class _FakeClient:
    def __init__(self):
        self.calls = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 201, {'id': 123}


class CLIParserTests(TestCase):
    def test_parser_exposes_basic_auth_only(self):
        parser = build_parser()
        option_strings = {opt for action in parser._actions for opt in action.option_strings}

        self.assertIn('--username', option_strings)
        self.assertIn('--password', option_strings)

        self.assertNotIn('--auth-mode', option_strings)
        self.assertNotIn('--token', option_strings)
        self.assertNotIn('--api-key', option_strings)
        self.assertNotIn('--api-key-header', option_strings)


class CLICommandRoutingTests(TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_create_root_ca_routes_to_root_workflow(self):
        args = self.parser.parse_args(
            [
                '--username', 'admin@local.host',
                '--password', 'pass1234',
                'create-root-ca',
                '--name', 'Root CLI Test',
                '--country-name', 'US',
                '--state-or-province-name', 'New York',
                '--locality-name', 'New York',
                '--organization-name', 'PKI Workbench',
                '--common-name', 'Root CLI Test',
            ]
        )
        client = _FakeClient()

        args.func(client, args)

        self.assertEqual(len(client.calls), 1)
        method, path, payload = client.calls[0]
        self.assertEqual(method, 'POST')
        self.assertEqual(path, 'workflows/root-cas/')
        self.assertEqual(payload['name'], 'Root CLI Test')

    def test_issue_certificate_generate_mode_routes_to_issue_workflow(self):
        args = self.parser.parse_args(
            [
                '--username', 'admin@local.host',
                '--password', 'pass1234',
                'issue-certificate',
                '--issuer-ca-id', '7',
                '--name', 'Leaf CLI Test',
                '--mode', 'generate',
                '--country-name', 'US',
                '--state-or-province-name', 'New York',
                '--locality-name', 'New York',
                '--organization-name', 'PKI Workbench',
                '--common-name', 'leaf.example.com',
            ]
        )
        client = _FakeClient()

        args.func(client, args)

        self.assertEqual(len(client.calls), 1)
        method, path, payload = client.calls[0]
        self.assertEqual(method, 'POST')
        self.assertEqual(path, 'workflows/certificates/')
        self.assertEqual(payload['issuer_ca_id'], 7)

    def test_issue_certificate_csr_mode_routes_to_sign_csr_workflow(self):
        args = self.parser.parse_args(
            [
                '--username', 'admin@local.host',
                '--password', 'pass1234',
                'issue-certificate',
                '--issuer-ca-id', '7',
                '--name', 'BYOK CLI Test',
                '--mode', 'csr',
                '--generate-csr',
            ]
        )
        client = _FakeClient()

        with patch('pki_cli.commands.issue_certificate.generate_csr_from_args', return_value='CSR-PEM'):
            args.func(client, args)

        self.assertEqual(len(client.calls), 1)
        method, path, payload = client.calls[0]
        self.assertEqual(method, 'POST')
        self.assertEqual(path, 'cas/7/sign-csr/')
        self.assertEqual(payload['csr_pem'], 'CSR-PEM')


class APIClientTests(TestCase):
    def test_api_client_requires_basic_credentials(self):
        with self.assertRaises(ValueError):
            APIClient(base_url='http://localhost:8000/api/', username='', password='pass1234', timeout=30)

        with self.assertRaises(ValueError):
            APIClient(base_url='http://localhost:8000/api/', username='admin@local.host', password=None, timeout=30)
