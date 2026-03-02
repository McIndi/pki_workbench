from django.contrib import admin

from .models import CertificateAuthority, CertificateProfile, CertificateSigningRequest, PrivateKey, SignedCertificate


@admin.register(PrivateKey)
class PrivateKeyAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'algorithm', 'curve_name', 'is_encrypted', 'created_at')
	search_fields = ('name',)


@admin.register(CertificateSigningRequest)
class CertificateSigningRequestAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'private_key', 'created_at')
	search_fields = ('name',)


@admin.register(SignedCertificate)
class SignedCertificateAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'issued_by', 'serial_number', 'not_valid_before', 'not_valid_after', 'created_at')
	search_fields = ('name', 'serial_number')


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'parent', 'depth', 'certification_depth', 'created_at')
	search_fields = ('name',)


@admin.register(CertificateProfile)
class CertificateProfileAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'is_ca', 'days_valid', 'key_algorithm', 'created_at')
	search_fields = ('name',)
