from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import CertificateProfile, SignedCertificate
from .workflows import create_root_certificate_authority, issue_signed_certificate


class PKIApiTests(APITestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(email='api-user@example.com', password='safe-password-123')
        self.other_user = user_model.objects.create_user(email='other-api-user@example.com', password='safe-password-123')

        self.subject = {
            'country_name': 'US',
            'state_or_province_name': 'New York',
            'locality_name': 'New York',
            'organization_name': 'PKI Workbench',
            'common_name': 'API Root',
        }

    def test_dashboard_requires_authentication(self):
        response = self.client.get('/api/dashboard/')
        self.assertIn(response.status_code, {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN})

    def test_api_root_lists_all_endpoint_groups(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/api/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('schema', response.data)
        self.assertIn('dashboard', response.data)
        self.assertIn('cas', response.data)
        self.assertIn('certificates', response.data)
        self.assertIn('profiles', response.data)
        self.assertIn('workflows', response.data)

    def test_openapi_schema_includes_workflow_and_resource_paths(self):
        self.client.force_authenticate(self.user)
        response = self.client.get('/api/schema/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        paths = response.data.get('paths', {})
        self.assertIn('/api/cas/', paths)
        self.assertIn('/api/certificates/', paths)
        self.assertIn('/api/profiles/', paths)
        self.assertIn('/api/dashboard/', paths)
        self.assertIn('/api/workflows/root-cas/', paths)
        self.assertIn('/api/workflows/intermediate-cas/', paths)
        self.assertIn('/api/workflows/certificates/', paths)
        self.assertIn('/api/workflows/profiles/from-certificate/', paths)

    def test_dashboard_returns_counts_and_tree(self):
        self.client.force_authenticate(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='API Dashboard Root',
            subject=self.subject,
            certification_depth=3,
        )
        issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='API Dashboard Cert',
            subject={**self.subject, 'common_name': 'api.example.com'},
            days_valid=30,
        )
        CertificateProfile.objects.create(owner=self.user, name='API Dashboard Profile')

        response = self.client.get('/api/dashboard/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['counts']['certificate_authorities'], 1)
        self.assertEqual(response.data['counts']['certificates'], 2)
        self.assertEqual(response.data['counts']['profiles'], 1)
        self.assertEqual(len(response.data['ca_tree']), 1)

    def test_profile_crud_is_owner_scoped(self):
        own_profile = CertificateProfile.objects.create(owner=self.user, name='Own API Profile')
        CertificateProfile.objects.create(owner=self.other_user, name='Other API Profile')

        self.client.force_authenticate(self.user)
        list_response = self.client.get('/api/profiles/')
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        returned_ids = {item['id'] for item in list_response.data}
        self.assertIn(own_profile.id, returned_ids)
        self.assertEqual(len(returned_ids), 1)

        update_response = self.client.patch(f'/api/profiles/{own_profile.id}/', {'description': 'Updated'}, format='json')
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)

    def test_issue_certificate_workflow_endpoint(self):
        root = create_root_certificate_authority(
            owner=self.user,
            name='API Workflow Root',
            subject=self.subject,
            certification_depth=3,
        )

        self.client.force_authenticate(self.user)
        response = self.client.post(
            '/api/workflows/certificates/',
            {
                'issuer_ca_id': root.id,
                'name': 'Workflow API Cert',
                'country_name': 'US',
                'state_or_province_name': 'New York',
                'locality_name': 'New York',
                'organization_name': 'PKI Workbench',
                'organizational_unit_name': 'API',
                'common_name': 'workflow.example.com',
                'email_address': '',
                'days_valid': 365,
                'key_algorithm': 'rsa',
                'curve_name': 'secp256r1',
                'key_size': 2048,
                'public_exponent': 65537,
                'passphrase': '',
                'issuer_key_passphrase': '',
                'san_dns_names': 'workflow.example.com',
                'ku_digital_signature': True,
                'ku_key_encipherment': True,
                'ku_critical': True,
                'eku_server_auth': True,
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(SignedCertificate.objects.filter(owner=self.user, name='Workflow API Cert').exists())
