from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.urls import reverse_lazy
from django.views.generic import UpdateView

from .forms import ProfileForm


class ProfileView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    template_name = 'accounts/profile.html'
    form_class = ProfileForm
    success_url = reverse_lazy('profile')
    success_message = 'Profile updated.'

    def get_object(self, queryset=None):
        return self.request.user.profile
