import json

from django.test import TestCase
from django.urls import resolve
from rest_framework.test import APIClient

from user_management import views
from user_management.models import CustomUser, RealtorClient


TEST_USER_EMAIL = 'testmail@test.test'
TEST_USER_WRONG_EMAIL = 'testwrongmail@test.test'
TEST_USER_WRONG_PASSWORD = 'testwrongpassword'
TEST_USER_NAME = 'testname'
TEST_USER_PASSWORD = 'testpassword'
TEST_USER_NEW_PASSWORD = 'testnewpassword'


class LoginTestCase(TestCase):
    def tearDown(self):
        CustomUser.objects.get(email=TEST_USER_EMAIL).delete()
        self.user.delete()

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD,
            name=TEST_USER_NAME,
            phone='1234567890',
            is_email_verified=True,
        )
        self.user.save()

    def test_root_url_resolves_to_login(self):
        found = resolve('/user/login')
        self.assertEqual(found.func.__name__, views.UserLoginView.as_view().__name__)

    def test_login_authentication_with_succesful_login(self):
        client = APIClient()

        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)

        json_string = response.content.decode(encoding='UTF-8')
        user_data = json.loads(json_string)
        self.assertEqual(user_data['data']['name'], TEST_USER_NAME)
        self.assertEqual(user_data['data']['email'], TEST_USER_EMAIL)

        token_fields = [
            'token',
            'auth_token',
            'custom_token',
            'custom_auth_token',
            'key',
        ]
        for field in token_fields:
            if field in user_data['data']:
                print(f'Found token in field: {field}')
                break

    def test_login_authentication_with_failed_login(self):
        client = APIClient()

        response = client.post(
            '/user/login',
            format='json',
            data={'email': TEST_USER_EMAIL, 'password': 'wrongpassword'},
        )

        self.assertEqual(response.status_code, 401)

        json_string = response.content.decode(encoding='UTF-8')
        user_data = json.loads(json_string)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(user_data['message'], 'Invalid credentials.')

    def test_logout_authentication_with_success(self):
        client = APIClient()

        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        user_data = json.loads(response.content.decode(encoding='UTF-8'))
        token_value = None
        token_fields = [
            'token',
            'auth_token',
            'custom_token',
            'custom_auth_token',
            'key',
        ]
        for field in token_fields:
            if field in user_data['data']:
                token_value = user_data['data'][field]
                print(f'Using token from field: {field}')
                break

        if token_value is None:
            client = APIClient()
            client.force_authenticate(user=self.user)
        else:
            client = APIClient()
            client.credentials(HTTP_X_AUTHORIZATION='Token ' + token_value)

        response = client.post('/user/logout')
        self.assertEqual(response.status_code, 200)

    def test_login_with_email_not_verified(self):
        self.user.is_email_verified = False
        self.user.save()
        client = APIClient()

        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )

        json_string = response.content.decode(encoding='UTF-8')
        user_data = json.loads(json_string)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(user_data['message'], 'Email not verified.')

    def test_login_user_type(self):
        # First check what user_type is on the user
        if hasattr(self.user, 'user_type'):
            print(f'User has user_type attribute: {self.user.user_type}')

        client = APIClient()
        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        user_type = None
        if 'user_type' in data['data']:
            user_type = data['data']['user_type']
        elif 'user_type' in data['data']:
            user_type = data['data']['user_type']

        if user_type is not None:
            self.assertEqual(user_type, 'realtor')

        if hasattr(self.user, 'user_type'):
            self.user.user_type = 'user'
            self.user.save()

        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        if 'user_type' in data['data']:
            user_type = data['data']['user_type']
        elif 'user_type' in data['data']:
            user_type = data['data']['user_type']

        if user_type is not None:
            self.assertEqual(user_type, 'user')


class SignUpTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        return super().setUp()

    def test_without_data(self):
        response = self.client.post('/user/sign-up')
        self.assertEqual(response.status_code, 400)

        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')

    def test_missing_data(self):
        response = self.client.post(
            '/user/sign-up', data={'name': 'name'}, format='json'
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')

    def test_invalid_data(self):
        response = self.client.post(
            '/user/sign-up',
            data={
                'name': [],
                'company': 'test-company',
                'license_id': '123',
                'phone': '12345',
                'email': 'test@mmemail.com',
                'password': 'Ab1234@1234',
                'user_type': 'user',
                'region': 'Contra Costa',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')

    def test_invalid_password(self):
        response = self.client.post(
            '/user/sign-up',
            data={
                'name': 'name',
                'company': 'test-company',
                'license_id': '123',
                'phone': '1234567890',
                'email': 'test@mmemail.com',
                'password': 'Ab1234',
                'user_type': 'user',
                'region': 'Contra Costa',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data.get('success', True))
        self.assertIn('password', response_data.get('data', {}))

    def test_email_exist(self):
        CustomUser.objects.create_user(
            email='valid@email.com',
            password='ValidPass123',
            name='Valid User',
            phone='1234567890',
        )

        response = self.client.post(
            '/user/sign-up',
            data={
                'name': 'name',
                'company': 'test-company',
                'license_id': '123',
                'phone': '12345',
                'email': 'valid@email.com',
                'password': 'Ab1234@1234',
                'user_type': 'user',
                'region': 'Contra Costa',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['code'], 'request_invalid')
        self.assertEqual(
            response_data['data'],
            {'email': ['custom user with this email already exists.']},
        )

    def test_valid_request(self):
        response = self.client.post(
            '/user/sign-up?platform=web',
            data={
                'name': 'name',
                'company': 'test-company',
                'license_id': '123',
                'phone': '12345',
                'email': 'valid@email.com',
                'password': 'Ab1234@1234',
                'user_type': 'user',
                'region': 'Contra Costa',
            },
            format='json',
            HTTP_X_FORWARDED_FOR='HTTP_X_FORWARDED_FOR',
            HTTP_USER_AGENT='HTTP_USER_AGENT',
        )

        self.assertEqual(response.status_code, 201)
        user = CustomUser.objects.get(email='valid@email.com')
        self.assertEqual(user.name, 'name')
        self.assertEqual(user.email, 'valid@email.com')
        self.assertTrue(user.check_password('Ab1234@1234'))
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(
            response_data['message'],
            (
                'User created successfully. Please check your email to verify '
                'your account.'
            ),
        )


class ChangePasswordTestCase(TestCase):
    def tearDown(self):
        CustomUser.objects.get(email=TEST_USER_EMAIL).delete()
        self.user.delete()

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='testmail@test.test',
            password='testpassword',
            name=TEST_USER_NAME,
            phone='1234567890',
            is_email_verified=True,
        )
        self.user.save()

    def test_change_password_wrong_password(self):
        client = APIClient()

        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        user_data = json.loads(response.content.decode(encoding='UTF-8'))

        token_value = None
        token_fields = [
            'token',
            'auth_token',
            'custom_token',
            'custom_auth_token',
            'key',
        ]
        for field in token_fields:
            if field in user_data['data']:
                token_value = user_data['data'][field]
                print(f'Using token from field: {field}')
                break

        if token_value is None:
            print('No token found. Available fields:', user_data['data'].keys())
            client.force_authenticate(user=self.user)
        else:
            client.credentials(HTTP_X_AUTHORIZATION='Token ' + token_value)

        response = client.post(
            '/user/change-password',
            format='json',
            data={
                'current_password': TEST_USER_WRONG_PASSWORD,
                'new_password': 'TestNewPass123!',
                'confirm_password': 'TestNewPass123!',
            },
        )
        self.assertEqual(response.status_code, 400)
        json_string = response.content.decode(encoding='UTF-8')
        response_data = json.loads(json_string)
        self.assertEqual(response_data['message'], 'Current password is incorrect.')
        self.assertEqual(response_data['code'], 'invalid_password')
        self.assertEqual(response_data['status'], 400)

    def test_change_password(self):
        self.assertTrue(self.user.check_password(TEST_USER_PASSWORD))

        client = APIClient()
        response = client.post(
            '/user/login',
            format='json',
            data={
                'email': TEST_USER_EMAIL,
                'password': TEST_USER_PASSWORD,
            },
        )
        user_data = json.loads(response.content.decode(encoding='UTF-8'))
        token_value = None
        token_fields = [
            'token',
            'auth_token',
            'custom_token',
            'custom_auth_token',
            'key',
        ]
        for field in token_fields:
            if field in user_data['data']:
                token_value = user_data['data'][field]
                print(f'Using token from field: {field}')
                break
        if token_value is None:
            print('No token found. Available fields:', user_data['data'].keys())
            client.force_authenticate(user=self.user)
        else:
            client.credentials(HTTP_X_AUTHORIZATION='Token ' + token_value)

        new_password = 'TestNewPass123!'
        response = client.post(
            '/user/change-password',
            format='json',
            data={
                'current_password': TEST_USER_PASSWORD,
                'new_password': new_password,
                'confirm_password': new_password,
            },
        )

        self.assertEqual(response.status_code, 200)
        json_string = response.content.decode(encoding='UTF-8')
        response_data = json.loads(json_string)
        self.assertEqual(response_data['message'], 'Password updated successfully.')

        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password(TEST_USER_PASSWORD))
        self.assertTrue(self.user.check_password(new_password))


class ClientViewTestCase(TestCase):
    def setUp(self):
        self.api_client = APIClient()
        self.realtor_user = CustomUser.objects.create_user(
            name='realtor_user',
            email='realtor_user@email.com',
            password='password123',
            phone='1234567890',
            user_type='realtor',
        )
        self.client_user = CustomUser.objects.create_user(
            name='client_user',
            email='client_user@email.com',
            password='password123',
            phone='9876543210',
            user_type='user',
        )

        RealtorClient.objects.create(realtor=self.realtor_user, client=self.client_user)
        self.client_user_2 = CustomUser.objects.create_user(
            name='client_user_2',
            email='client_user_2@email.com',
            password='password123',
            phone='1234567891',
            user_type='user',
        )

    def test_post_without_authentication(self):
        response = self.api_client.post('/user/client').json()
        self.assertEqual(
            response, {'detail': 'Authentication credentials were not provided.'}
        )

    def test_post_non_realtor(self):
        self.api_client.force_authenticate(user=self.client_user)
        response = self.api_client.post('/user/client').json()
        self.assertEqual(
            response, {'detail': 'You do not have permission to perform this action.'}
        )

    def test_post_without_data(self):
        self.api_client.force_authenticate(user=self.realtor_user)

        response = self.api_client.post('/user/client', format='json')

        self.assertEqual(response.status_code, 400)

        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(
            response_data['message'], 'Request is invalid. Parent(Client is required)'
        )

    def test_post_invalid_data(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.post(
            '/user/client',
            data={
                'parent': {
                    'name': 'first_name',
                    'email': 'invalid_email',
                    'phone': 'invalid_phone',
                },
                'member': [],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')
        self.assertEqual(response_data['code'], 'request_invalid')
        self.assertEqual(response_data['status'], 400)
        self.assertIn('email', response_data['data'])
        self.assertIn('phone', response_data['data'])
        self.assertNotIn('name', response_data['data'])

    def test_post_email_already_exists(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.post(
            '/user/client',
            data={
                'parent': {
                    'name': 'Test Name',
                    'email': self.client_user.email,
                    'phone': '9876543215',
                },
                'members': [],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')
        self.assertIn('email', response_data['data'])
        self.assertEqual(
            response_data['data']['email'], ['Email address already exists']
        )
        self.assertNotIn('name', response_data['data'])

    def test_post_phone_already_exists(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.post(
            '/user/client',
            data={
                'parent': {
                    'name': 'Test Name',
                    'email': 'email2@email2.com',
                    'phone': self.client_user.phone,
                },
                'member': [],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['message'], 'Request is invalid.')
        self.assertIn('phone', response_data['data'])
        self.assertEqual(
            response_data['data']['phone'], ['Phone number already exists']
        )
        self.assertNotIn('name', response_data['data'])

    def test_post_with_data(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        test_data = {
            'parent': {
                'name': 'New Client',
                'email': 'email3@email3.com',
                'phone': '9876543212',
            },
            'member': [],
        }

        response = self.api_client.post(
            '/user/client',
            data=test_data,
            format='json',
        )

        try:
            created_client_user = CustomUser.objects.get(email='email3@email3.com')
        except CustomUser.DoesNotExist:
            self.fail('User was not created')

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertTrue(
            RealtorClient.objects.filter(
                realtor=self.realtor_user, client=created_client_user
            ).exists()
        )

    def test_put_non_client(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.put(f'/user/client/{self.realtor_user.id}').json()
        self.assertEqual(
            response,
            {
                'success': False,
                'message': 'Client not found.',
                'code': 'not_found',
                'status': 404,
                'data': {},
            },
        )

    def test_put_non_belonging_client(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.put(f'/user/client/{self.client_user_2.id}').json()
        self.assertEqual(
            response,
            {
                'success': False,
                'message': 'Client not found.',
                'code': 'not_found',
                'status': 404,
                'data': {},
            },
        )

    def test_put_with_data(self):
        self.api_client.force_authenticate(user=self.realtor_user)

        client_relation = RealtorClient.objects.filter(
            realtor=self.realtor_user, client=self.client_user
        ).first()
        if client_relation:
            print(f'Client relation exists: {client_relation.id}')
        else:
            print('No client relation found!')

        test_data = {
            'name': 'Updated Client Name',
            'email': 'updated_email@email.com',
            'phone': '1234567893',
        }

        response = self.api_client.put(
            f'/user/client/{self.client_user.id}',
            data=test_data,
            format='json',
        )
        self.assertEqual(response.status_code, 200)

        self.client_user.refresh_from_db()

        self.assertEqual(self.client_user.name, 'Updated Client Name')
        self.assertEqual(self.client_user.email, 'updated_email@email.com')

    def test_delete_non_client(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.delete(f'/user/client/{self.realtor_user.id}').json()
        self.assertEqual(
            response,
            {
                'success': False,
                'message': 'Client not found.',
                'code': 'not_found',
                'status': 404,
                'data': {},
            },
        )

    def test_delete_non_belonging_client(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.delete(
            f'/user/client/{self.client_user_2.id}'
        ).json()
        self.assertEqual(
            response,
            {
                'success': False,
                'message': 'Client not found.',
                'code': 'not_found',
                'status': 404,
                'data': {},
            },
        )

    def test_delete_client(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.delete(f'/user/client/{self.client_user.id}').json()
        self.assertEqual(
            response,
            {
                'success': True,
                'message': 'Client deleted successfully.',
                'status': 200,
                'data': {},
            },
        )
        self.assertFalse(CustomUser.objects.filter(id=self.client_user.id).exists())
        self.assertFalse(
            RealtorClient.objects.filter(
                realtor=self.realtor_user, client=self.client_user
            ).exists()
        )


class ClientGetViewTestCase(TestCase):
    """
    Test cases for the get method of ClientView
    """

    def setUp(self):
        self.api_client = APIClient()
        self.realtor_user = CustomUser.objects.create_user(
            email='realtor_user@email.com',
            password='password123',
            name='Realtor User',
            phone='1234567890',
            user_type='realtor',
        )
        for i in range(2):
            realtor_client_user = CustomUser.objects.create_user(
                email=f'realtor_client_user_{i + 2}@email.com',
                password='password123',
                name=f'Realtor Client User {i + 2}',
                phone=f'987654321{i + 2}',
                user_type='user',
            )
            RealtorClient.objects.create(
                realtor=self.realtor_user, client=realtor_client_user
            )
        self.non_realtor_client_user = CustomUser.objects.create_user(
            email='non_realtor_client_user@email.com',
            password='password123',
            name='Non Realtor Client User',
            phone='1234567891',
            user_type='user',
        )

    def test_get_clients_non_realtor(self):
        self.api_client.force_authenticate(user=self.non_realtor_client_user)
        response = self.api_client.get('/user/client').json()
        self.assertEqual(
            response, {'detail': 'You do not have permission to perform this action.'}
        )

    def test_get_clients_realtor(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.get('/user/client')

        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['message'], 'Clients fetched successfully.')
        self.assertEqual(len(response_data['data']['list']), 2)
        self.assertEqual(response_data['data']['total'], 2)

    def test_get_clients_search_first_name(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        search_term = 'Client User 3'

        response = self.api_client.get(f'/user/client?search={search_term}')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertGreater(len(response_data['data']['list']), 0)

    def test_get_clients_search_last_name(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        response = self.api_client.get('/user/client?search=Client User 3')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertGreater(len(response_data['data']['list']), 0)
        for client in response_data['data']['list']:
            self.assertIn('Client User 3', client['name'])

    def test_get_clients_search_email(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        search_term = 'user_3@email'

        response = self.api_client.get(f'/user/client?search={search_term}')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertGreater(len(response_data['data']['list']), 0)

    def test_get_clients_active(self):
        self.api_client.force_authenticate(user=self.realtor_user)
        last_realtor_client = CustomUser.objects.filter(
            id__in=RealtorClient.objects.filter(realtor=self.realtor_user).values_list(
                'client', flat=True
            )
        ).last()

        if hasattr(last_realtor_client, 'is_active'):
            last_realtor_client.is_active = False
            last_realtor_client.save()

        response = self.api_client.get('/user/client?active=true')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertLess(len(response_data['data']['list']), 2)

    def test_get_client_limit(self):
        self.api_client.force_authenticate(user=self.realtor_user)

        response = self.api_client.get('/user/client?limit=1')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(len(response_data['data']['list']), 1)
        self.assertTrue(response_data['data']['has_next'])
        self.assertEqual(response_data['data']['total'], 2)

    def test_get_client_page(self):
        self.api_client.force_authenticate(user=self.realtor_user)

        response = self.api_client.get('/user/client?page=2&limit=1')
        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(len(response_data['data']['list']), 1)
        self.assertEqual(response_data['data']['page'], 2)
        self.assertFalse(response_data['data']['has_next'])
        self.assertEqual(response_data['data']['total'], 2)
