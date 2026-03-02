from django.shortcuts import render
from django.utils import timezone
from django.views.generic import TemplateView

from pki.models import CertificateAuthority, CertificateProfile, SignedCertificate


def _build_ca_tree(authorities):
    node_map = {
        authority.id: {
            'authority': authority,
            'children': [],
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


class HomeView(TemplateView):
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        if not user.is_authenticated:
            context.update(
                {
                    'dashboard': None,
                }
            )
            return context

        all_cas = CertificateAuthority.objects.filter(owner=user).select_related('parent').order_by('depth', 'name')
        certificates = SignedCertificate.objects.filter(owner=user).select_related('issued_by').order_by('not_valid_after', 'name')
        editable_profiles = CertificateProfile.objects.filter(owner=user).order_by('name')

        now = timezone.now()
        expiring_certificates = []
        for certificate in certificates[:10]:
            expiry_delta = certificate.not_valid_after - now
            expiring_certificates.append(
                {
                    'certificate': certificate,
                    'days_until_expiry': expiry_delta.days,
                    'is_expired': certificate.not_valid_after <= now,
                }
            )

        context.update(
            {
                'dashboard': {
                    'ca_count': all_cas.count(),
                    'certificate_count': certificates.count(),
                    'profile_count': editable_profiles.count(),
                    'expiring_certificates': expiring_certificates,
                    'ca_tree': _build_ca_tree(list(all_cas)),
                },
                'all_cas': all_cas,
                'editable_profiles': editable_profiles,
            }
        )
        return context


def custom_404(request, exception):
    return render(request, '404.html', status=404)


def custom_500(request):
    return render(request, '500.html', status=500)
