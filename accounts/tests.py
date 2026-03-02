from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import Profile


class SanityTests(TestCase):
    def test_sanity_assertion(self):
        self.assertTrue(True)


class UserProfileTests(TestCase):
    def test_create_user_with_email(self):
        user = get_user_model().objects.create_user(email='test@example.com', password='safe-password-123')
        self.assertEqual(user.email, 'test@example.com')

    def test_profile_auto_created(self):
        user = get_user_model().objects.create_user(email='profile@example.com', password='safe-password-123')
        self.assertTrue(Profile.objects.filter(user=user).exists())


class ViewSmokeTests(TestCase):
    def test_home_page_loads(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)

    def test_login_page_loads(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
