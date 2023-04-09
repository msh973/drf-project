from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APITestCase, APIRequestFactory
from api import views
from .utils import APIViewTestCase, override_api_settings
from rest_framework_simplejwt import  authentication
from importlib import reload
from datetime import timedelta
from rest_framework_simplejwt import serializers
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, SlidingToken
from rest_framework_simplejwt.views import TokenViewBase
from unittest.mock import patch
from django.utils import timezone
from rest_framework_simplejwt.utils import (
    aware_utcnow,
    datetime_from_epoch,
    datetime_to_epoch,
)
from django.urls import reverse
from rest_framework import status


User = get_user_model()
AuthToken = api_settings.AUTH_TOKEN_CLASSES[0]

class UsersManagersTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.backend = authentication.JWTAuthentication()

        self.fake_token = b"TokenMcTokenface"
        self.fake_header = b"Bearer " + self.fake_token

    def test_get_header(self):
        # Should return None if no authorization header
        request = self.factory.get("/test-url/")
        self.assertIsNone(self.backend.get_header(request))

        # Should pull correct header off request
        request = self.factory.get("/test-url/", HTTP_AUTHORIZATION=self.fake_header)
        self.assertEqual(self.backend.get_header(request), self.fake_header)

        # Should work for unicode headers
        request = self.factory.get(
            "/test-url/", HTTP_AUTHORIZATION=self.fake_header.decode("utf-8")
        )
        self.assertEqual(self.backend.get_header(request), self.fake_header)

        # Should work with the x_access_token
        with override_api_settings(AUTH_HEADER_NAME="HTTP_X_ACCESS_TOKEN"):
            # Should pull correct header off request when using X_ACCESS_TOKEN
            request = self.factory.get(
                "/test-url/", HTTP_X_ACCESS_TOKEN=self.fake_header
            )
            self.assertEqual(self.backend.get_header(request), self.fake_header)

            # Should work for unicode headers when using
            request = self.factory.get(
                "/test-url/", HTTP_X_ACCESS_TOKEN=self.fake_header.decode("utf-8")
            )
            self.assertEqual(self.backend.get_header(request), self.fake_header)

    def test_get_raw_token(self):
        # Should return None if header lacks correct type keyword
        with override_api_settings(AUTH_HEADER_TYPES="JWT"):
            reload(authentication)
            self.assertIsNone(self.backend.get_raw_token(self.fake_header))
        reload(authentication)

        # Should return None if an empty AUTHORIZATION header is sent
        self.assertIsNone(self.backend.get_raw_token(b""))

        # Should raise error if header is malformed
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_raw_token(b"Bearer one two")

        with self.assertRaises(AuthenticationFailed):
            self.backend.get_raw_token(b"Bearer")

        # Otherwise, should return unvalidated token in header
        self.assertEqual(self.backend.get_raw_token(self.fake_header), self.fake_token)

        # Should return token if header has one of many valid token types
        with override_api_settings(AUTH_HEADER_TYPES=("JWT", "Bearer")):
            reload(authentication)
            self.assertEqual(
                self.backend.get_raw_token(self.fake_header),
                self.fake_token,
            )
        reload(authentication)

    def test_get_validated_token(self):
        # Should raise InvalidToken if token not valid
        token = AuthToken()
        token.set_exp(lifetime=-timedelta(days=1))
        with self.assertRaises(InvalidToken):
            self.backend.get_validated_token(str(token))

        # Otherwise, should return validated token
        token.set_exp()
        self.assertEqual(
            self.backend.get_validated_token(str(token)).payload, token.payload
        )

        # Should not accept tokens not included in AUTH_TOKEN_CLASSES
        sliding_token = SlidingToken()
        with override_api_settings(
                AUTH_TOKEN_CLASSES=("rest_framework_simplejwt.tokens.AccessToken",)
        ):
            with self.assertRaises(InvalidToken) as e:
                self.backend.get_validated_token(str(sliding_token))

            messages = e.exception.detail["messages"]
            self.assertEqual(1, len(messages))
            self.assertEqual(
                {
                    "token_class": "AccessToken",
                    "token_type": "access",
                    "message": "Token has wrong type",
                },
                messages[0],
            )

        # Should accept tokens included in AUTH_TOKEN_CLASSES
        access_token = AccessToken()
        sliding_token = SlidingToken()
        with override_api_settings(
                AUTH_TOKEN_CLASSES=(
                        "rest_framework_simplejwt.tokens.AccessToken",
                        "rest_framework_simplejwt.tokens.SlidingToken",
                )
        ):
            self.backend.get_validated_token(str(access_token))
            self.backend.get_validated_token(str(sliding_token))

    def test_get_user(self):
        payload = {"some_other_id": "foo"}

        # Should raise error if no recognizable user identification
        with self.assertRaises(InvalidToken):
            self.backend.get_user(payload)

        payload[api_settings.USER_ID_CLAIM] = 42

        # Should raise exception if user not found
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        u = User.objects.create_user(username="markhamill")
        u.is_active = False
        u.save()

        payload[api_settings.USER_ID_CLAIM] = getattr(u, api_settings.USER_ID_FIELD)

        # Should raise exception if user is inactive
        with self.assertRaises(AuthenticationFailed):
            self.backend.get_user(payload)

        u.is_active = True
        u.save()

        # Otherwise, should return correct user
        self.assertEqual(self.backend.get_user(payload).id, u.id)

    class TestTokenObtainPairView(APIViewTestCase):
        view_name = "token_obtain_pair"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn(User.USERNAME_FIELD, res.data)
            self.assertIn("password", res.data)

            res = self.view_post(data={User.USERNAME_FIELD: self.username})
            self.assertEqual(res.status_code, 400)
            self.assertIn("password", res.data)

            res = self.view_post(data={"password": self.password})
            self.assertEqual(res.status_code, 400)
            self.assertIn(User.USERNAME_FIELD, res.data)

        def test_credentials_wrong(self):
            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": "test_user",
                }
            )
            self.assertEqual(res.status_code, 401)
            self.assertIn("detail", res.data)

        def test_user_inactive(self):
            self.user.is_active = False
            self.user.save()

            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )
            self.assertEqual(res.status_code, 401)
            self.assertIn("detail", res.data)

        def test_success(self):
            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn("access", res.data)
            self.assertIn("refresh", res.data)

        def test_update_last_login(self):
            self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )

            # verify last_login is not updated
            user = User.objects.get(username=self.username)
            self.assertEqual(user.last_login, None)

            # verify last_login is updated
            with override_api_settings(UPDATE_LAST_LOGIN=True):
                reload(serializers)
                self.view_post(
                    data={
                        User.USERNAME_FIELD: self.username,
                        "password": self.password,
                    }
                )
                user = User.objects.get(username=self.username)
                self.assertIsNotNone(user.last_login)
                self.assertGreaterEqual(timezone.now(), user.last_login)

            reload(serializers)

    class TestTokenRefreshView(APIViewTestCase):
        view_name = "token_refresh"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn("refresh", res.data)

        def test_it_should_return_401_if_token_invalid(self):
            token = RefreshToken()
            del token["exp"]

            res = self.view_post(data={"refresh": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

            token.set_exp(lifetime=-timedelta(seconds=1))

            res = self.view_post(data={"refresh": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_return_access_token_if_everything_ok(self):
            refresh = RefreshToken()
            refresh["test_claim"] = "arst"

            # View returns 200
            now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

            with patch("rest_framework_simplejwt.tokens.aware_utcnow") as fake_aware_utcnow:
                fake_aware_utcnow.return_value = now

                res = self.view_post(data={"refresh": str(refresh)})

            self.assertEqual(res.status_code, 200)

            access = AccessToken(res.data["access"])

            self.assertEqual(refresh["test_claim"], access["test_claim"])
            self.assertEqual(
                access["exp"], datetime_to_epoch(now + api_settings.ACCESS_TOKEN_LIFETIME)
            )

    class TestTokenObtainSlidingView(APIViewTestCase):
        view_name = "token_obtain_sliding"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn(User.USERNAME_FIELD, res.data)
            self.assertIn("password", res.data)

            res = self.view_post(data={User.USERNAME_FIELD: self.username})
            self.assertEqual(res.status_code, 400)
            self.assertIn("password", res.data)

            res = self.view_post(data={"password": self.password})
            self.assertEqual(res.status_code, 400)
            self.assertIn(User.USERNAME_FIELD, res.data)

        def test_credentials_wrong(self):
            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": "test_user",
                }
            )
            self.assertEqual(res.status_code, 401)
            self.assertIn("detail", res.data)

        def test_user_inactive(self):
            self.user.is_active = False
            self.user.save()

            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )
            self.assertEqual(res.status_code, 401)
            self.assertIn("detail", res.data)

        def test_success(self):
            res = self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn("token", res.data)

        def test_update_last_login(self):
            self.view_post(
                data={
                    User.USERNAME_FIELD: self.username,
                    "password": self.password,
                }
            )

            # verify last_login is not updated
            user = User.objects.get(username=self.username)
            self.assertEqual(user.last_login, None)

            # verify last_login is updated
            with override_api_settings(UPDATE_LAST_LOGIN=True):
                reload(serializers)
                self.view_post(
                    data={
                        User.USERNAME_FIELD: self.username,
                        "password": self.password,
                    }
                )
                user = User.objects.get(username=self.username)
                self.assertIsNotNone(user.last_login)
                self.assertGreaterEqual(timezone.now(), user.last_login)

            reload(serializers)

    class TestTokenRefreshSlidingView(APIViewTestCase):
        view_name = "token_refresh_sliding"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn("token", res.data)

        def test_it_should_return_401_if_token_invalid(self):
            token = SlidingToken()
            del token["exp"]

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

            token.set_exp(lifetime=-timedelta(seconds=1))

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_return_401_if_token_has_no_refresh_exp_claim(self):
            token = SlidingToken()
            del token[api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM]

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_return_401_if_token_has_refresh_period_expired(self):
            token = SlidingToken()
            token.set_exp(
                api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM, lifetime=-timedelta(seconds=1)
            )

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_update_token_exp_claim_if_everything_ok(self):
            now = aware_utcnow()

            token = SlidingToken()
            exp = now + api_settings.SLIDING_TOKEN_LIFETIME - timedelta(seconds=1)
            token.set_exp(
                from_time=now,
                lifetime=api_settings.SLIDING_TOKEN_LIFETIME - timedelta(seconds=1),
            )

            # View returns 200
            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 200)

            # Expiration claim has moved into future
            new_token = SlidingToken(res.data["token"])
            new_exp = datetime_from_epoch(new_token["exp"])

            self.assertTrue(exp < new_exp)

    class TestTokenVerifyView(APIViewTestCase):
        view_name = "token_verify"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn("token", res.data)

        def test_it_should_return_401_if_token_invalid(self):
            token = SlidingToken()
            del token["exp"]

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

            token.set_exp(lifetime=-timedelta(seconds=1))

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_return_200_if_everything_okay(self):
            token = RefreshToken()

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(len(res.data), 0)

        def test_it_should_ignore_token_type(self):
            token = RefreshToken()
            token[api_settings.TOKEN_TYPE_CLAIM] = "fake_type"

            res = self.view_post(data={"token": str(token)})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(len(res.data), 0)

    class TestTokenBlacklistView(APIViewTestCase):
        view_name = "token_blacklist"

        def setUp(self):
            self.username = "test_user"
            self.password = "test_password"

            self.user = User.objects.create_user(
                username=self.username,
                password=self.password,
            )

        def test_fields_missing(self):
            res = self.view_post(data={})
            self.assertEqual(res.status_code, 400)
            self.assertIn("refresh", res.data)

        def test_it_should_return_401_if_token_invalid(self):
            token = RefreshToken()
            del token["exp"]

            res = self.view_post(data={"refresh": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

            token.set_exp(lifetime=-timedelta(seconds=1))

            res = self.view_post(data={"refresh": str(token)})
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.data["code"], "token_not_valid")

        def test_it_should_return_if_everything_ok(self):
            refresh = RefreshToken()
            refresh["test_claim"] = "arst"

            # View returns 200
            now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

            with patch("rest_framework_simplejwt.tokens.aware_utcnow") as fake_aware_utcnow:
                fake_aware_utcnow.return_value = now

                res = self.view_post(data={"refresh": str(refresh)})

            self.assertEqual(res.status_code, 200)

            self.assertDictEqual(res.data, {})

        def test_it_should_return_401_if_token_is_blacklisted(self):
            refresh = RefreshToken()
            refresh["test_claim"] = "arst"

            # View returns 200
            now = aware_utcnow() - api_settings.ACCESS_TOKEN_LIFETIME / 2

            with patch("rest_framework_simplejwt.tokens.aware_utcnow") as fake_aware_utcnow:
                fake_aware_utcnow.return_value = now

                res = self.view_post(data={"refresh": str(refresh)})

            self.assertEqual(res.status_code, 200)

            self.view_name = "token_refresh"
            res = self.view_post(data={"refresh": str(refresh)})
            # make sure other tests are not affected
            del self.view_name

            self.assertEqual(res.status_code, 401)

    class TestCustomTokenView(APIViewTestCase):
        def test_custom_view_class(self):
            class CustomTokenView(TokenViewBase):
                serializer_class = serializers.TokenObtainPairSerializer

            factory = APIRequestFactory()
            view = CustomTokenView.as_view()
            request = factory.post("/", {}, format="json")
            res = view(request)
            self.assertEqual(res.status_code, 400)


class TestAPIViews(APITestCase):
    def create_user(self):
        url = reverse('UC')
        data = {'username':'testuser', 'email': 'test@test.com' ,'password': 'test', 'is_developer': 'True', 'is_projectmanager': 'True'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def create_list_project(self):
        url = reverse('PCL')
        data = {'name': 'testproject'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def create_Developer_task(self):
        url = reverse('DTC')
        data = {'name': 'testtask', 'description':'test', 'completed':'False', 'Project': '1', 'user':'1'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def create_Projectmanager_task(self):
        url = reverse('PJTC')
        data = {'name': 'testtask', 'description':'test', 'completed':'False', 'Project': '1', 'user':'1'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def Task_user_list(self):
        url = reverse('UTL')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def Task_Project_list(self):
        url = reverse('TL/1')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def update_assignee(self):
        url = reverse('AU')
        data = {'username': 'testuser2', 'project':'1', 'is_developer': 'True'}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)





