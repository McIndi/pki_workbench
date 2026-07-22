from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.urls import reverse
from django.utils import timezone
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .api_serializers import CertificateAuthoritySerializer, CertificateProfileSerializer, SignedCertificateSerializer
from .forms import (
    CreateProfileFromCertificateForm,
    ImportCAForm,
    IntermediateCAForm,
    IssueCertificateForm,
    RootCAForm,
    SignCSRForm,
)
from .models import CertificateAuthority, CertificateProfile, CertificateSigningRequest, PrivateKey, SignedCertificate
from .workflows import (
    create_certificate_profile_from_certificate,
    create_intermediate_certificate_authority,
    create_root_certificate_authority,
    import_certificate_authority,
    issue_signed_certificate_from_csr,
    issue_signed_certificate,
)


class APIRootIndexAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cas_detail_template = request.build_absolute_uri(reverse('api-cas-detail', args=[0])).replace('/0/', '/{id}/')
        certificates_detail_template = request.build_absolute_uri(reverse('api-certificates-detail', args=[0])).replace(
            '/0/', '/{id}/'
        )
        profiles_detail_template = request.build_absolute_uri(reverse('api-profiles-detail', args=[0])).replace(
            '/0/', '/{id}/'
        )
        return Response(
            {
                'schema': request.build_absolute_uri(reverse('api-schema')),
                'dashboard': request.build_absolute_uri(reverse('api-dashboard')),
                'cas': {
                    'list': request.build_absolute_uri(reverse('api-cas-list')),
                    'detail_template': cas_detail_template,
                    'chain_template': request.build_absolute_uri(reverse('api-cas-chain', args=[0])).replace(
                        '/0/', '/{id}/'
                    ),
                    'children_template': request.build_absolute_uri(reverse('api-cas-children', args=[0])).replace(
                        '/0/', '/{id}/'
                    ),
                    'sign_csr_template': request.build_absolute_uri(reverse('api-cas-sign-csr', args=[0])).replace(
                        '/0/', '/{id}/'
                    ),
                },
                'certificates': {
                    'list': request.build_absolute_uri(reverse('api-certificates-list')),
                    'detail_template': certificates_detail_template,
                },
                'profiles': {
                    'list': request.build_absolute_uri(reverse('api-profiles-list')),
                    'detail_template': profiles_detail_template,
                },
                'workflows': {
                    'create_root_ca': request.build_absolute_uri(reverse('api-workflow-root-ca')),
                    'create_intermediate_ca': request.build_absolute_uri(reverse('api-workflow-intermediate-ca')),
                    'import_ca': request.build_absolute_uri(reverse('api-workflow-import-ca')),
                    'issue_certificate': request.build_absolute_uri(reverse('api-workflow-certificate')),
                    'delete_certificate': request.build_absolute_uri(reverse('api-workflow-delete-certificate')),
                    'delete_ca': request.build_absolute_uri(reverse('api-workflow-delete-ca')),
                    'delete_private_key': request.build_absolute_uri(reverse('api-workflow-delete-private-key')),
                    'delete_csr': request.build_absolute_uri(reverse('api-workflow-delete-csr')),
                    'derive_profile_from_certificate': request.build_absolute_uri(
                        reverse('api-workflow-profile-from-certificate')
                    ),
                },
            }
        )


def _build_ca_tree(authorities):
    node_map = {
        authority.id: {
            'id': authority.id,
            'name': authority.name,
            'depth': authority.depth,
            'children': [],
            'workbench_url': reverse('pki-ca-workbench', kwargs={'ca_id': authority.id}),
        }
        for authority in authorities
    }
    roots = []
    for authority in authorities:
        node = node_map[authority.id]
        if authority.parent_id and authority.parent_id in node_map:
            node_map[authority.parent_id]['children'].append(node)
        else:
            roots.append(node)
    return roots


class CertificateAuthorityViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CertificateAuthoritySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CertificateAuthority.objects.filter(owner=self.request.user).select_related('parent').order_by('depth', 'name')

    @action(detail=True, methods=['get'])
    def chain(self, request, pk=None):
        authority = self.get_object()
        chain = []
        node = authority
        while node is not None:
            chain.append(node)
            node = node.parent
        chain.reverse()
        serializer = self.get_serializer(chain, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def children(self, request, pk=None):
        authority = self.get_object()
        serializer = self.get_serializer(
            authority.children.select_related('parent').all().order_by('name'),
            many=True,
        )
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='sign-csr')
    def sign_csr(self, request, pk=None):
        authority = self.get_object()
        profile_queryset = CertificateProfile.objects.filter(owner__in=[None, request.user]).order_by('owner_id', 'name')
        payload = {
            **request.data,
            'certificate_profile': request.data.get('certificate_profile_id'),
        }
        form = SignCSRForm(payload, profile_queryset=profile_queryset)
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            certificate = issue_signed_certificate_from_csr(
                owner=request.user,
                issuer_authority=authority,
                name=form.cleaned_data['name'],
                csr_pem=form.cleaned_data['csr_pem'],
                certificate_profile=form.cleaned_data.get('certificate_profile'),
                issuer_key_passphrase=form.cleaned_data.get('issuer_key_passphrase') or None,
                days_valid=form.cleaned_data['days_valid'],
                key_usage=form.key_usage_payload(),
                extended_key_usages=form.extended_key_usage_payload(),
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(SignedCertificateSerializer(certificate, context={'request': request}).data, status=status.HTTP_201_CREATED)


class SignedCertificateViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SignedCertificateSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return (
            SignedCertificate.objects.filter(owner=self.request.user)
            .select_related('issued_by', 'private_key')
            .order_by('-created_at')
        )


class CertificateProfileViewSet(viewsets.ModelViewSet):
    serializer_class = CertificateProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CertificateProfile.objects.filter(owner=self.request.user).order_by('name')

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class DashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        authorities = list(
            CertificateAuthority.objects.filter(owner=request.user).select_related('parent').order_by('depth', 'name')
        )
        certificates = list(
            SignedCertificate.objects.filter(owner=request.user)
            .select_related('issued_by', 'private_key')
            .order_by('not_valid_after', 'name')
        )
        profiles = CertificateProfile.objects.filter(owner=request.user)

        now = timezone.now()
        expiring = []
        for cert in certificates[:10]:
            delta = cert.not_valid_after - now
            expiring.append(
                {
                    'certificate_id': cert.id,
                    'name': cert.name,
                    'not_valid_after': cert.not_valid_after,
                    'days_until_expiry': delta.days,
                    'is_expired': cert.not_valid_after <= now,
                    'detail_url': reverse('pki-issued-certificate-detail', kwargs={'certificate_id': cert.id}),
                }
            )

        return Response(
            {
                'counts': {
                    'certificate_authorities': len(authorities),
                    'certificates': len(certificates),
                    'profiles': profiles.count(),
                },
                'expiring_certificates': expiring,
                'ca_tree': _build_ca_tree(authorities),
            }
        )


class RootCACreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)
    country_name = serializers.CharField(max_length=2)
    state_or_province_name = serializers.CharField(max_length=128)
    locality_name = serializers.CharField(max_length=128)
    organization_name = serializers.CharField(max_length=255)
    common_name = serializers.CharField(max_length=255)
    email_address = serializers.EmailField(required=False, allow_blank=True)
    certification_depth = serializers.IntegerField(min_value=1, max_value=10, default=3)
    days_valid = serializers.IntegerField(min_value=1, default=3650)
    key_algorithm = serializers.CharField(default='rsa')
    curve_name = serializers.CharField(required=False, allow_blank=True, default='secp256r1')
    key_size = serializers.IntegerField(required=False, default=2048)
    public_exponent = serializers.IntegerField(required=False, default=65537)
    passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to protect the newly generated root CA private key (optional, can be left blank)',
    )


class RootCAWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = RootCACreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        form = RootCAForm(serializer.validated_data)
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            authority = create_root_certificate_authority(
                owner=request.user,
                name=form.cleaned_data['name'],
                subject=form.subject_payload(),
                certification_depth=form.cleaned_data['certification_depth'],
                key_algorithm=form.cleaned_data['key_algorithm'],
                curve_name=form.cleaned_data.get('curve_name') or 'secp256r1',
                key_size=form.cleaned_data.get('key_size') or 2048,
                public_exponent=form.cleaned_data.get('public_exponent') or 65537,
                passphrase=form.cleaned_data.get('passphrase') or None,
                days_valid=form.cleaned_data['days_valid'],
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(CertificateAuthoritySerializer(authority, context={'request': request}).data, status=status.HTTP_201_CREATED)


class IntermediateWorkflowSerializer(serializers.Serializer):
    parent_ca_id = serializers.IntegerField()
    name = serializers.CharField(max_length=150)
    country_name = serializers.CharField(max_length=2)
    state_or_province_name = serializers.CharField(max_length=128)
    locality_name = serializers.CharField(max_length=128)
    organization_name = serializers.CharField(max_length=255)
    organizational_unit_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    common_name = serializers.CharField(max_length=255)
    email_address = serializers.EmailField(required=False, allow_blank=True)
    days_valid = serializers.IntegerField(min_value=1, default=1825)
    key_algorithm = serializers.CharField(default='rsa')
    curve_name = serializers.CharField(required=False, allow_blank=True, default='secp256r1')
    key_size = serializers.IntegerField(required=False, default=2048)
    public_exponent = serializers.IntegerField(required=False, default=65537)
    passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to protect the newly generated intermediate CA private key (optional, can be left blank)',
    )
    parent_key_passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to unlock the parent CA private key for signing. Required only if the parent CA key is encrypted.',
    )


class IntermediateCAWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = IntermediateWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            parent_ca = CertificateAuthority.objects.get(id=data['parent_ca_id'], owner=request.user)
        except CertificateAuthority.DoesNotExist:
            return Response({'detail': 'Parent certificate authority not found.'}, status=status.HTTP_404_NOT_FOUND)

        form = IntermediateCAForm(data)
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            authority = create_intermediate_certificate_authority(
                owner=request.user,
                parent_authority=parent_ca,
                name=form.cleaned_data['name'],
                subject=form.subject_payload(),
                key_algorithm=form.cleaned_data['key_algorithm'],
                curve_name=form.cleaned_data.get('curve_name') or 'secp256r1',
                key_size=form.cleaned_data.get('key_size') or 2048,
                public_exponent=form.cleaned_data.get('public_exponent') or 65537,
                passphrase=form.cleaned_data.get('passphrase') or None,
                parent_key_passphrase=form.cleaned_data.get('parent_key_passphrase') or None,
                days_valid=form.cleaned_data['days_valid'],
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(CertificateAuthoritySerializer(authority, context={'request': request}).data, status=status.HTTP_201_CREATED)


class ImportCAWorkflowSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)
    certificate_pem = serializers.CharField()
    private_key_pem = serializers.CharField()
    key_passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to decrypt the imported CA private key. Required only if the key is encrypted.',
    )
    parent_ca_id = serializers.IntegerField(required=False, allow_null=True)
    certification_depth = serializers.IntegerField(min_value=1, max_value=10, default=3)


class ImportCAWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ImportCAWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        parent_ca = None
        if data.get('parent_ca_id'):
            try:
                parent_ca = CertificateAuthority.objects.get(id=data['parent_ca_id'], owner=request.user)
            except CertificateAuthority.DoesNotExist:
                return Response({'detail': 'Parent certificate authority not found.'}, status=status.HTTP_404_NOT_FOUND)

        form = ImportCAForm(data, owner=request.user)
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            authority = import_certificate_authority(
                owner=request.user,
                name=form.cleaned_data['name'],
                certificate_pem=form.cleaned_data['certificate_pem'],
                private_key_pem=form.cleaned_data['private_key_pem'],
                key_passphrase=form.cleaned_data.get('key_passphrase') or None,
                parent_authority=parent_ca,
                certification_depth=form.cleaned_data['certification_depth'],
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(CertificateAuthoritySerializer(authority, context={'request': request}).data, status=status.HTTP_201_CREATED)


class CertificateWorkflowSerializer(serializers.Serializer):
    issuer_ca_id = serializers.IntegerField()
    name = serializers.CharField(max_length=150)
    certificate_profile_id = serializers.IntegerField(required=False, allow_null=True)
    country_name = serializers.CharField(max_length=2)
    state_or_province_name = serializers.CharField(max_length=128)
    locality_name = serializers.CharField(max_length=128)
    organization_name = serializers.CharField(max_length=255)
    organizational_unit_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    common_name = serializers.CharField(max_length=255)
    email_address = serializers.EmailField(required=False, allow_blank=True)
    days_valid = serializers.IntegerField(min_value=1, default=365)
    key_algorithm = serializers.CharField(default='rsa')
    curve_name = serializers.CharField(required=False, allow_blank=True, default='secp256r1')
    key_size = serializers.IntegerField(required=False, default=2048)
    public_exponent = serializers.IntegerField(required=False, default=65537)
    passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to protect the newly generated certificate private key (optional, can be left blank)',
    )
    issuer_key_passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Password to unlock the issuing CA private key for signing. Required only if the issuing CA key is encrypted.',
    )
    san_dns_names = serializers.CharField(required=False, allow_blank=True)

    ku_digital_signature = serializers.BooleanField(required=False, default=True)
    ku_content_commitment = serializers.BooleanField(required=False, default=False)
    ku_key_encipherment = serializers.BooleanField(required=False, default=True)
    ku_data_encipherment = serializers.BooleanField(required=False, default=False)
    ku_key_agreement = serializers.BooleanField(required=False, default=False)
    ku_key_cert_sign = serializers.BooleanField(required=False, default=False)
    ku_crl_sign = serializers.BooleanField(required=False, default=False)
    ku_encipher_only = serializers.BooleanField(required=False, default=False)
    ku_decipher_only = serializers.BooleanField(required=False, default=False)
    ku_critical = serializers.BooleanField(required=False, default=True)

    eku_server_auth = serializers.BooleanField(required=False, default=True)
    eku_client_auth = serializers.BooleanField(required=False, default=False)
    eku_code_signing = serializers.BooleanField(required=False, default=False)
    eku_email_protection = serializers.BooleanField(required=False, default=False)
    eku_time_stamping = serializers.BooleanField(required=False, default=False)
    eku_ocsp_signing = serializers.BooleanField(required=False, default=False)


class IssueCertificateWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CertificateWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            issuer = CertificateAuthority.objects.get(id=data['issuer_ca_id'], owner=request.user)
        except CertificateAuthority.DoesNotExist:
            return Response({'detail': 'Issuer certificate authority not found.'}, status=status.HTTP_404_NOT_FOUND)

        profile_queryset = CertificateProfile.objects.filter(owner__in=[None, request.user]).order_by('owner_id', 'name')
        form_data = {
            **data,
            'certificate_profile': data.get('certificate_profile_id'),
        }
        form = IssueCertificateForm(form_data, profile_queryset=profile_queryset)
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            certificate = issue_signed_certificate(
                owner=request.user,
                issuer_authority=issuer,
                name=form.cleaned_data['name'],
                subject=form.subject_payload(),
                key_algorithm=form.cleaned_data['key_algorithm'],
                curve_name=form.cleaned_data.get('curve_name') or 'secp256r1',
                key_size=form.cleaned_data.get('key_size') or 2048,
                public_exponent=form.cleaned_data.get('public_exponent') or 65537,
                certificate_profile=form.cleaned_data.get('certificate_profile'),
                passphrase=form.cleaned_data.get('passphrase') or None,
                issuer_key_passphrase=form.cleaned_data.get('issuer_key_passphrase') or None,
                days_valid=form.cleaned_data['days_valid'],
                san_dns_names=form.san_dns_name_list(),
                key_usage=form.key_usage_payload(),
                extended_key_usages=form.extended_key_usage_payload(),
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(SignedCertificateSerializer(certificate, context={'request': request}).data, status=status.HTTP_201_CREATED)


class DeriveProfileWorkflowSerializer(serializers.Serializer):
    certificate_id = serializers.IntegerField()
    name = serializers.CharField(max_length=150)
    description = serializers.CharField(required=False, allow_blank=True)


class DeriveProfileFromCertificateWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeriveProfileWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            certificate = SignedCertificate.objects.get(id=data['certificate_id'], owner=request.user)
        except SignedCertificate.DoesNotExist:
            return Response({'detail': 'Certificate not found.'}, status=status.HTTP_404_NOT_FOUND)

        form = CreateProfileFromCertificateForm({'name': data['name'], 'description': data.get('description', '')})
        if not form.is_valid():
            return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = create_certificate_profile_from_certificate(
                owner=request.user,
                certificate=certificate,
                name=form.cleaned_data['name'],
                description=form.cleaned_data.get('description') or '',
            )
        except ValidationError as exc:
            return Response({'detail': exc.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response(CertificateProfileSerializer(profile).data, status=status.HTTP_201_CREATED)


class DeleteCertificateWorkflowSerializer(serializers.Serializer):
    certificate_id = serializers.IntegerField()


class DeleteCertificateWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteCertificateWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        certificate_id = serializer.validated_data['certificate_id']
        try:
            certificate = SignedCertificate.objects.get(id=certificate_id, owner=request.user)
        except SignedCertificate.DoesNotExist:
            return Response({'detail': 'Certificate not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            certificate.delete()
        except ProtectedError:
            return Response(
                {'detail': 'Cannot delete certificate because it is currently referenced.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({'detail': 'Certificate deleted successfully.'}, status=status.HTTP_200_OK)


class DeleteCAWorkflowSerializer(serializers.Serializer):
    target_ca_id = serializers.IntegerField()


class DeleteCAWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteCAWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        target_ca_id = serializer.validated_data['target_ca_id']
        try:
            target_ca = CertificateAuthority.objects.get(id=target_ca_id, owner=request.user)
        except CertificateAuthority.DoesNotExist:
            return Response({'detail': 'Certificate authority not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            target_ca.delete()
        except ProtectedError:
            return Response(
                {'detail': 'Cannot delete certificate authority because it has dependent records.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({'detail': 'Certificate authority deleted successfully.'}, status=status.HTTP_200_OK)


class DeletePrivateKeyWorkflowSerializer(serializers.Serializer):
    private_key_id = serializers.IntegerField()


class DeletePrivateKeyWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeletePrivateKeyWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        private_key_id = serializer.validated_data['private_key_id']
        try:
            private_key = PrivateKey.objects.get(id=private_key_id, owner=request.user)
        except PrivateKey.DoesNotExist:
            return Response({'detail': 'Private key not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            private_key.delete()
        except ProtectedError:
            return Response(
                {'detail': 'Cannot delete private key because it is currently referenced.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({'detail': 'Private key deleted successfully.'}, status=status.HTTP_200_OK)


class DeleteCSRWorkflowSerializer(serializers.Serializer):
    csr_id = serializers.IntegerField()


class DeleteCSRWorkflowAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteCSRWorkflowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        csr_id = serializer.validated_data['csr_id']
        try:
            csr = CertificateSigningRequest.objects.get(id=csr_id, owner=request.user)
        except CertificateSigningRequest.DoesNotExist:
            return Response({'detail': 'CSR not found.'}, status=status.HTTP_404_NOT_FOUND)

        csr.delete()
        return Response({'detail': 'CSR deleted successfully.'}, status=status.HTTP_200_OK)
