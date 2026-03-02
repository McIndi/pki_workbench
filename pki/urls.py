from django.urls import path

from .views import (
    CAWorkbenchView,
    CertificateProfileUpdateView,
    IssuedCertificateDetailView,
    IssuedCertificateDownloadView,
    RootCACreateView,
)

urlpatterns = [
    path('pki/root/create/', RootCACreateView.as_view(), name='pki-create-root-ca'),
    path('pki/ca/<int:ca_id>/workbench/', CAWorkbenchView.as_view(), name='pki-ca-workbench'),
    path('pki/profiles/<int:profile_id>/edit/', CertificateProfileUpdateView.as_view(), name='pki-profile-edit'),
    path('pki/certificate/<int:certificate_id>/', IssuedCertificateDetailView.as_view(), name='pki-issued-certificate-detail'),
    path(
        'pki/certificate/<int:certificate_id>/download/<str:artifact>/',
        IssuedCertificateDownloadView.as_view(),
        name='pki-issued-certificate-download',
    ),
]
