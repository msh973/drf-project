from django.contrib.auth import get_user_model
from django.test import TestCase


class UsersManagersTests(TestCase):

    def test_create_user(self):
        User = get_user_model()
        user = User.objects.create_user(username="normal2", password="foo")
        self.assertEqual(user.username, "normal2")
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_developer)
        self.assertFalse(user.is_projectmanager)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        try:
            # username is None for the AbstractUser option
            # username does not exist for the AbstractBaseUser option
            self.assertEqual(user.email, '')
        except AttributeError:
            pass
        with self.assertRaises(TypeError):
            User.objects.create_user()
        #with self.assertRaises(TypeError):
        #    User.objects.create_user(username="")
        #with self.assertRaises(ValueError):
           # User.objects.create_user(username="", password="foo")

    def test_create_superuser(self):
        User = get_user_model()
        admin_user = User.objects.create_superuser(username="super4", password="foo")
        self.assertEqual(admin_user.username, "super4")
        self.assertTrue(admin_user.is_active)
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_developer)
        self.assertTrue(admin_user.is_projectmanager)
        self.assertTrue(admin_user.is_superuser)
        try:
            # username is None for the AbstractUser option
            # username does not exist for the AbstractBaseUser option
            self.assertEqual(admin_user.email, '')
        except AttributeError:
            pass
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username="super4", password="foo", is_superuser=False)
