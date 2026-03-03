from rest_framework import serializers

from .models import CertificateAuthority, CertificateProfile, SignedCertificate


class CertificateAuthoritySerializer(serializers.ModelSerializer):
    parent_id = serializers.IntegerField(source='parent.id', allow_null=True, read_only=True)
    is_root = serializers.BooleanField(read_only=True)
    workbench_url = serializers.SerializerMethodField()

    class Meta:
        model = CertificateAuthority
        fields = [
            'id',
            'name',
            'parent_id',
            'depth',
            'certification_depth',
            'is_root',
            'created_at',
            'workbench_url',
        ]

    def get_workbench_url(self, obj):
        request = self.context.get('request')
        if not request:
            return ''
        return request.build_absolute_uri(f'/pki/ca/{obj.id}/workbench/')


class SignedCertificateSerializer(serializers.ModelSerializer):
    issued_by_id = serializers.IntegerField(source='issued_by.id', allow_null=True, read_only=True)
    private_key_algorithm = serializers.SerializerMethodField()
    detail_url = serializers.SerializerMethodField()
    download_urls = serializers.SerializerMethodField()

    class Meta:
        model = SignedCertificate
        fields = [
            'id',
            'name',
            'serial_number',
            'not_valid_before',
            'not_valid_after',
            'issued_by_id',
            'private_key_algorithm',
            'created_at',
            'detail_url',
            'download_urls',
        ]

    def get_detail_url(self, obj):
        request = self.context.get('request')
        if not request:
            return ''
        return request.build_absolute_uri(f'/pki/certificate/{obj.id}/')

    def get_private_key_algorithm(self, obj):
        if obj.private_key is None:
            return None
        return obj.private_key.algorithm

    def get_download_urls(self, obj):
        request = self.context.get('request')
        if not request:
            return {}
        base = f'/pki/certificate/{obj.id}/download/'
        return {
            'pubcert': request.build_absolute_uri(f'{base}pubcert/'),
            'pubcert_chain': request.build_absolute_uri(f'{base}pubcert-chain/'),
            'csr': request.build_absolute_uri(f'{base}csr/'),
            'pair_zip': request.build_absolute_uri(f'{base}pair-zip/'),
        }


class CertificateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CertificateProfile
        fields = [
            'id',
            'name',
            'description',
            'is_ca',
            'path_length',
            'days_valid',
            'key_algorithm',
            'curve_name',
            'key_size',
            'public_exponent',
            'country_name',
            'state_or_province_name',
            'locality_name',
            'organization_name',
            'organizational_unit_name',
            'common_name',
            'email_address',
            'ku_digital_signature',
            'ku_content_commitment',
            'ku_key_encipherment',
            'ku_data_encipherment',
            'ku_key_agreement',
            'ku_key_cert_sign',
            'ku_crl_sign',
            'ku_encipher_only',
            'ku_decipher_only',
            'ku_critical',
            'eku_server_auth',
            'eku_client_auth',
            'eku_code_signing',
            'eku_email_protection',
            'eku_time_stamping',
            'eku_ocsp_signing',
            'created_at',
        ]
        read_only_fields = ['id', 'created_at']
