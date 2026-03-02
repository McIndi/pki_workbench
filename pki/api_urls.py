from django.urls import include, path
from rest_framework.renderers import JSONOpenAPIRenderer
from rest_framework.schemas import get_schema_view
from rest_framework.routers import DefaultRouter

from .api_views import (
    APIRootIndexAPIView,
    CertificateAuthorityViewSet,
    CertificateProfileViewSet,
    DashboardAPIView,
    DeriveProfileFromCertificateWorkflowAPIView,
    IntermediateCAWorkflowAPIView,
    IssueCertificateWorkflowAPIView,
    RootCAWorkflowAPIView,
    SignedCertificateViewSet,
)

router = DefaultRouter()
router.register(r'cas', CertificateAuthorityViewSet, basename='api-cas')
router.register(r'certificates', SignedCertificateViewSet, basename='api-certificates')
router.register(r'profiles', CertificateProfileViewSet, basename='api-profiles')

schema_view = get_schema_view(
    title='PKI Workbench API',
    description='REST API for PKI Workbench certificate authority and issuance workflows.',
    version='1.0.0',
    renderer_classes=[JSONOpenAPIRenderer],
)

urlpatterns = [
    path('', APIRootIndexAPIView.as_view(), name='api-root'),
    path('schema/', schema_view, name='api-schema'),
    path('', include(router.urls)),
    path('dashboard/', DashboardAPIView.as_view(), name='api-dashboard'),
    path('workflows/root-cas/', RootCAWorkflowAPIView.as_view(), name='api-workflow-root-ca'),
    path('workflows/intermediate-cas/', IntermediateCAWorkflowAPIView.as_view(), name='api-workflow-intermediate-ca'),
    path('workflows/certificates/', IssueCertificateWorkflowAPIView.as_view(), name='api-workflow-certificate'),
    path(
        'workflows/profiles/from-certificate/',
        DeriveProfileFromCertificateWorkflowAPIView.as_view(),
        name='api-workflow-profile-from-certificate',
    ),
]
