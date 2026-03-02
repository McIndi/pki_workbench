from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .api_serializers import CertificateAuthoritySerializer, CertificateProfileSerializer, SignedCertificateSerializer
from .forms import CreateProfileFromCertificateForm, IntermediateCAForm, IssueCertificateForm, RootCAForm
from .models import CertificateAuthority, CertificateProfile, SignedCertificate
from .workflows import (
    create_certificate_profile_from_certificate,
    create_intermediate_certificate_authority,
    create_root_certificate_authority,
    issue_signed_certificate,
)


class APIRootIndexAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                'schema': request.build_absolute_uri(reverse('api-schema')),
                'dashboard': request.build_absolute_uri(reverse('api-dashboard')),
                'cas': {
                    'list': request.build_absolute_uri(reverse('api-cas-list')),
                    'detail_template': request.build_absolute_uri('/api/cas/{id}/'),
                    'chain_template': request.build_absolute_uri('/api/cas/{id}/chain/'),
                    'children_template': request.build_absolute_uri('/api/cas/{id}/children/'),
                },
                'certificates': {
                    'list': request.build_absolute_uri(reverse('api-certificates-list')),
                    'detail_template': request.build_absolute_uri('/api/certificates/{id}/'),
                },
                'profiles': {
                    'list': request.build_absolute_uri(reverse('api-profiles-list')),
                    'detail_template': request.build_absolute_uri('/api/profiles/{id}/'),
                },
                'workflows': {
                    'create_root_ca': request.build_absolute_uri(reverse('api-workflow-root-ca')),
                    'create_intermediate_ca': request.build_absolute_uri(reverse('api-workflow-intermediate-ca')),
                    'issue_certificate': request.build_absolute_uri(reverse('api-workflow-certificate')),
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
            'workbench_url': f'/pki/ca/{authority.id}/workbench/',
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
                    'detail_url': f'/pki/certificate/{cert.id}/',
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
    passphrase = serializers.CharField(required=False, allow_blank=True)


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
    common_name = serializers.CharField(max_length=255)
    email_address = serializers.EmailField(required=False, allow_blank=True)
    days_valid = serializers.IntegerField(min_value=1, default=1825)
    key_algorithm = serializers.CharField(default='rsa')
    curve_name = serializers.CharField(required=False, allow_blank=True, default='secp256r1')
    key_size = serializers.IntegerField(required=False, default=2048)
    public_exponent = serializers.IntegerField(required=False, default=65537)
    passphrase = serializers.CharField(required=False, allow_blank=True)
    parent_key_passphrase = serializers.CharField(required=False, allow_blank=True)


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
    passphrase = serializers.CharField(required=False, allow_blank=True)
    issuer_key_passphrase = serializers.CharField(required=False, allow_blank=True)
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
