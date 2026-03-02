from django import forms

from .models import Profile


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['theme_mode']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['theme_mode'].widget.attrs.update({'class': 'form-select'})
