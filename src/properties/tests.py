import random
import string
from unittest.mock import patch

from chat.models import Chat
from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from django.test import TestCase
from properties.models import (
    Comparable,
    Disclosure,
    Offer,
    Property,
    PropertyMedia,
    RealtorProperty,
)
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.test import APIClient

from user_management.models import CustomUser


User = get_user_model()


class PropertyViewTestCase(TestCase):
    fixtures = ['property.json']

    def setUp(self):
        self.maxDiff = None
        self.user = get_user_model().objects.create_user(
            email='testmail@test.test',
            password='testpassword',
            name='Test Name',
            phone='1234567890',
            user_type='client',
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_unauthorized_request(self):
        self.client.force_authenticate(None)
        response = self.client.get('/properties/').json()
        self.assertDictEqual(
            response, {'detail': 'Authentication credentials were not provided.'}
        )

    def test_without_params(self):
        response = self.client.get('/properties/').json()

        normalized_list = []
        for prop in response['data']['list']:
            image_url = prop['image']
            if not image_url.startswith('/media/'):
                image_url = f'/media/{image_url}'

            normalized_list.append(
                {
                    'name': prop['name'],
                    'address': prop['address'],
                    'image': image_url,
                    'price': prop['price'],
                    'no_of_beds': prop['no_of_beds'],
                    'no_of_baths': prop['no_of_baths'],
                    'square_feet_size': prop['square_feet_size'],
                    'property_details': prop['property_details'],
                }
            )
        sorted_list = sorted(normalized_list, key=lambda x: x['name'])
        simplified_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': sorted_list,
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }
        expected_response = {
            'success': True,
            'message': 'Properties fetched successfully.',
            'status': 200,
            'data': {
                'list': [
                    {
                        'name': 'property_1',
                        'address': 'property_address_1',
                        'image': '/media/Screenshot_2025-03-14_at_12.55.09AM.png',
                        'price': 1,
                        'no_of_beds': 1,
                        'no_of_baths': 1,
                        'square_feet_size': 1,
                        'property_details': [],
                    },
                    {
                        'name': 'property_2',
                        'address': 'property_address_2',
                        'image': '/media/Screenshot_2025-03-14_at_12_4xTthfD.55.09AM.png',  # noqa: E501
                        'price': 2,
                        'no_of_beds': 2,
                        'no_of_baths': 2,
                        'square_feet_size': 2,
                        'property_details': [],
                    },
                    {
                        'name': 'property_3',
                        'address': 'property_address_3',
                        'image': '/media/Screenshot_2025-03-14_at_12_jL4veah.55.09AM.png',  # noqa: E501
                        'price': 3,
                        'no_of_beds': 3,
                        'no_of_baths': 3,
                        'square_feet_size': 3,
                        'property_details': [],
                    },
                    {
                        'name': 'property_4',
                        'address': 'property_address_4',
                        'image': '/media/Screenshot_2025-03-14_at_12_YttIMzO.55.09AM.png',  # noqa: E501
                        'price': 4,
                        'no_of_beds': 4,
                        'no_of_baths': 4,
                        'square_feet_size': 4,
                        'property_details': [],
                    },
                    {
                        'name': 'property_5',
                        'address': 'property_address_5',
                        'image': '/media/Screenshot_2025-03-14_at_12_X21E1gR.55.09AM.png',  # noqa: E501
                        'price': 5,
                        'no_of_beds': 5,
                        'no_of_baths': 5,
                        'square_feet_size': 5,
                        'property_details': [],
                    },
                ],
                'page': 1,
                'has_next': False,
                'total': 5,
            },
        }

        self.assertDictEqual(simplified_response, expected_response)

    def test_invalid_search_value(self):
        response = self.client.get('/properties/?search=invalid_value').json()
        self.assertDictEqual(
            response,
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': 200,
                'data': {
                    'list': [],
                    'page': 1,
                    'has_next': False,
                    'total': 0,
                },
            },
        )

    def test_search_by_name(self):
        response = self.client.get('/properties/?search=property_1').json()

        response_data = response['data']['list'][0]
        if not response_data['image'].startswith('/media/'):
            response_data['image'] = f'/media/{response_data["image"]}'

        filtered_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': [
                    {
                        'name': response_data['name'],
                        'address': response_data['address'],
                        'image': response_data['image'],
                        'price': response_data['price'],
                        'no_of_beds': response_data['no_of_beds'],
                        'no_of_baths': response_data['no_of_baths'],
                        'square_feet_size': response_data['square_feet_size'],
                        'property_details': response_data['property_details'],
                    }
                ],
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }

        self.assertDictEqual(
            filtered_response,
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': 200,
                'data': {
                    'list': [
                        {
                            'name': 'property_1',
                            'address': 'property_address_1',
                            'image': '/media/Screenshot_2025-03-14_at_12.55.09AM.png',
                            'price': 1,
                            'no_of_beds': 1,
                            'no_of_baths': 1,
                            'square_feet_size': 1,
                            'property_details': [],
                        },
                    ],
                    'page': 1,
                    'has_next': False,
                    'total': 1,
                },
            },
        )

    def test_search_by_address(self):
        response = self.client.get('/properties/?search=property_address_2').json()

        filtered_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': [
                    {
                        'name': response['data']['list'][0]['name'],
                        'address': response['data']['list'][0]['address'],
                        'image': (
                            f'/media/{response["data"]["list"][0]["image"]}'
                            if not response['data']['list'][0]['image'].startswith(
                                '/media/'
                            )
                            else response['data']['list'][0]['image']
                        ),
                        'price': response['data']['list'][0]['price'],
                        'no_of_beds': response['data']['list'][0]['no_of_beds'],
                        'no_of_baths': response['data']['list'][0]['no_of_baths'],
                        'square_feet_size': response['data']['list'][0][
                            'square_feet_size'
                        ],
                        'property_details': response['data']['list'][0][
                            'property_details'
                        ],
                    }
                ],
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }

        self.assertDictEqual(
            filtered_response,
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': 200,
                'data': {
                    'list': [
                        {
                            'name': 'property_2',
                            'address': 'property_address_2',
                            'image': '/media/Screenshot_2025-03-14_at_12_4xTthfD.55.09AM.png',  # noqa: E501
                            'price': 2,
                            'no_of_beds': 2,
                            'no_of_baths': 2,
                            'square_feet_size': 2,
                            'property_details': [],
                        },
                    ],
                    'page': 1,
                    'has_next': False,
                    'total': 1,
                },
            },
        )

    def test_partial_search(self):
        response = self.client.get('/properties/?search=address_2').json()

        normalized_list = []
        for prop in response['data']['list']:
            normalized_prop = {
                'name': prop['name'],
                'address': prop['address'],
                'image': (
                    f'/media/{prop["image"]}'
                    if not prop['image'].startswith('/media/')
                    else prop['image']
                ),
                'price': prop['price'],
                'no_of_beds': prop['no_of_beds'],
                'no_of_baths': prop['no_of_baths'],
                'square_feet_size': prop['square_feet_size'],
                'property_details': prop['property_details'],
            }
            normalized_list.append(normalized_prop)

        simplified_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': normalized_list,
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }

        self.assertDictEqual(
            simplified_response,
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': 200,
                'data': {
                    'list': [
                        {
                            'name': 'property_2',
                            'address': 'property_address_2',
                            'image': '/media/Screenshot_2025-03-14_at_12_4xTthfD.55.09AM.png',  # noqa: E501
                            'price': 2,
                            'no_of_beds': 2,
                            'no_of_baths': 2,
                            'square_feet_size': 2,
                            'property_details': [],
                        },
                    ],
                    'page': 1,
                    'has_next': False,
                    'total': 1,
                },
            },
        )

        self.assertDictEqual(
            simplified_response,
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': 200,
                'data': {
                    'list': [
                        {
                            'name': 'property_2',
                            'address': 'property_address_2',
                            'image': '/media/Screenshot_2025-03-14_at_12_4xTthfD.55.09AM.png',  # noqa: E501
                            'price': 2,
                            'no_of_beds': 2,
                            'no_of_baths': 2,
                            'square_feet_size': 2,
                            'property_details': [],
                        },
                    ],
                    'page': 1,
                    'has_next': False,
                    'total': 1,
                },
            },
        )

    def test_sort_by_price_ascending(self):
        response = self.client.get('/properties/?sort=price_ASC').json()

        normalized_list = []
        for prop in response['data']['list']:
            normalized_list.append(
                {
                    'name': prop['name'],
                    'address': prop['address'],
                    'price': prop['price'],
                    'no_of_beds': prop['no_of_beds'],
                    'no_of_baths': prop['no_of_baths'],
                    'square_feet_size': prop['square_feet_size'],
                    'property_details': prop['property_details'],
                }
            )

        prices = [prop['price'] for prop in normalized_list]
        self.assertEqual(prices, sorted(prices))

        simplified_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': normalized_list,
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }

        expected_response = {
            'success': True,
            'message': 'Properties fetched successfully.',
            'status': 200,
            'data': {
                'list': [
                    {
                        'name': 'property_1',
                        'address': 'property_address_1',
                        'price': 1,
                        'no_of_beds': 1,
                        'no_of_baths': 1,
                        'square_feet_size': 1,
                        'property_details': [],
                    },
                    {
                        'name': 'property_2',
                        'address': 'property_address_2',
                        'price': 2,
                        'no_of_beds': 2,
                        'no_of_baths': 2,
                        'square_feet_size': 2,
                        'property_details': [],
                    },
                    {
                        'name': 'property_3',
                        'address': 'property_address_3',
                        'price': 3,
                        'no_of_beds': 3,
                        'no_of_baths': 3,
                        'square_feet_size': 3,
                        'property_details': [],
                    },
                    {
                        'name': 'property_4',
                        'address': 'property_address_4',
                        'price': 4,
                        'no_of_beds': 4,
                        'no_of_baths': 4,
                        'square_feet_size': 4,
                        'property_details': [],
                    },
                    {
                        'name': 'property_5',
                        'address': 'property_address_5',
                        'price': 5,
                        'no_of_beds': 5,
                        'no_of_baths': 5,
                        'square_feet_size': 5,
                        'property_details': [],
                    },
                ],
                'page': 1,
                'has_next': False,
                'total': 5,
            },
        }

        self.assertDictEqual(simplified_response, expected_response)

    def test_sort_by_price_descending(self):
        response = self.client.get('/properties/?sort=price_DESC').json()
        simplified_response = {
            'success': response['success'],
            'message': response['message'],
            'status': response['status'],
            'data': {
                'list': [
                    {
                        'name': prop['name'],
                        'address': prop['address'],
                        'image': (
                            f'/media/{prop["image"]}'
                            if not prop['image'].startswith('/media/')
                            else prop['image']
                        ),
                        'price': prop['price'],
                        'no_of_beds': prop['no_of_beds'],
                        'no_of_baths': prop['no_of_baths'],
                        'square_feet_size': prop['square_feet_size'],
                        'property_details': prop['property_details'],
                    }
                    for prop in response['data']['list']
                ],
                'page': response['data']['page'],
                'has_next': response['data']['has_next'],
                'total': response['data']['total'],
            },
        }

        # Verify the response structure
        self.assertEqual(simplified_response['success'], True)
        self.assertEqual(
            simplified_response['message'], 'Properties fetched successfully.'
        )
        self.assertEqual(simplified_response['status'], 200)
        self.assertEqual(len(simplified_response['data']['list']), 5)
        self.assertEqual(simplified_response['data']['page'], 1)
        self.assertEqual(simplified_response['data']['has_next'], False)
        self.assertEqual(simplified_response['data']['total'], 5)

    def test_sort_by_date(self):
        response = self.client.get('/properties/?sort=date_DESC').json()
        self.assertEqual(response['success'], True)
        self.assertEqual(response['message'], 'Properties fetched successfully.')
        self.assertEqual(response['status'], 200)
        self.assertIn('data', response)
        self.assertIn('list', response['data'])
        self.assertGreater(len(response['data']['list']), 0)

    def test_sort_by_activity(self):
        response = self.client.get('/properties/?sort=activity_DESC').json()
        self.assertEqual(response['success'], True)
        self.assertEqual(response['message'], 'Properties fetched successfully.')
        self.assertEqual(response['status'], 200)
        self.assertIn('data', response)
        self.assertIn('list', response['data'])
        self.assertGreater(len(response['data']['list']), 0)

    def test_limit_param(self):
        response = self.client.get('/properties/?limit=1')
        response_data = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data['success'], True)
        self.assertEqual(response_data['message'], 'Properties fetched successfully.')

        self.assertEqual(response_data['data']['page'], 1)
        self.assertEqual(response_data['data']['has_next'], True)
        self.assertEqual(response_data['data']['total'], 5)

        properties = response_data['data']['list']
        self.assertEqual(len(properties), 1)

        prop = properties[0]
        self.assertIn('name', prop)
        self.assertIn('address', prop)

        image_path = prop['image']
        self.assertTrue(
            image_path.startswith(('media/', '/media/')) or '/' not in image_path,
            f'Image path should be in media directory or just filename: {image_path}',
        )

        self.assertIn('price', prop)
        self.assertIn('no_of_beds', prop)
        self.assertIn('no_of_baths', prop)
        self.assertIn('square_feet_size', prop)

    def test_page_param(self):
        options_response = self.client.options('/properties/')
        self.assertEqual(options_response.status_code, status.HTTP_200_OK)
        valid_user_id = self.user.id
        initial_response = self.client.get('/properties/', {'user_id': valid_user_id})
        self.assertEqual(
            initial_response.status_code,
            status.HTTP_200_OK,
            f'Expected 200 OK but got {initial_response.status_code}. '
            f'Response: {initial_response.json()}',
        )
        total_properties = Property.objects.count()
        self.assertGreaterEqual(
            total_properties, 2, 'Need at least 2 properties for pagination test'
        )  # noqa: E501
        response = self.client.get(
            '/properties/', {'user_id': valid_user_id, 'limit': 1, 'page': 2}
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
            f'Expected 200 OK but got {response.status_code}. '
            f'Response: {response.json()}',
        )

        response_data = response.json()
        self.assertIn('data', response_data)
        self.assertIn('list', response_data['data'])

        if len(response_data['data']['list']) == 0:
            self.fail(
                f'Page 2 returned empty results. Total properties: {total_properties}'
            )

        response_property = response_data['data']['list'][0]
        normalized_response = {
            'success': response_data['success'],
            'message': response_data['message'],
            'status': response_data['status'],
            'data': {
                'list': [
                    {
                        'name': response_property['name'],
                        'address': response_property['address'],
                        'image': (
                            f'/media/{response_property["image"]}'
                            if not response_property['image'].startswith('/media/')
                            else response_property['image']
                        ),
                        'price': response_property['price'],
                        'no_of_beds': response_property['no_of_beds'],
                        'no_of_baths': response_property['no_of_baths'],
                        'square_feet_size': response_property['square_feet_size'],
                        'property_details': response_property['property_details'],
                    }
                ],
                'page': response_data['data']['page'],
                'has_next': response_data['data']['has_next'],
                'total': response_data['data']['total'],
            },
        }

        self.assertEqual(normalized_response['data']['page'], 2)
        self.assertEqual(normalized_response['data']['has_next'], total_properties > 2)
        self.assertGreaterEqual(normalized_response['data']['total'], 2)
        self.assertEqual(len(normalized_response['data']['list']), 1)


class PropertyPostViewTestCase(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='testmail@test.test',
            password='testpassword',
            name='Test Name',
            phone='1234567890',
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_unauthorized_request(self):
        self.client.force_authenticate(None)
        response = self.client.post('/properties/').json()
        self.assertDictEqual(
            response, {'detail': 'Authentication credentials were not provided.'}
        )

    def test_without_data(self):
        response = self.client.post('/properties/', data={}, format='json').json()
        self.assertDictEqual(
            response,
            {
                'success': False,
                'message': 'Request is invalid.',
                'code': 'request_invalid',
                'status': 400,
                'data': {
                    'address': ['This field is required.'],
                },
            },
        )

    def test_with_data(self):
        self.client.force_authenticate(self.user)

        response = self.client.post(
            '/properties/',
            data={
                'name': 'property_1',
                'address': 'property_address_1',
                'price': 1,
                'no_of_beds': 1,
                'no_of_baths': 1,
                'square_feet_size': 1,
                'additional_information': 'property_additional_information_1',
                'note': 'Test note',
                'user_id': 1,
                'listing_id': 1,
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['message'], 'Property created successfully.')
        self.assertIn('id', response_data['data'])
        property = Property.objects.get(id=response_data['data']['id'])
        self.assertEqual(property.name, 'property_1')


class PropertyDetailsViewTestCase(TestCase):
    # fixtures = ['property.json', 'offers_comparables.json']

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='testmail@test.test',
            password='testpassword',
            name='Test Name',
            phone='1234567890',
        )
        # Create test property
        self.property = Property.objects.create(
            name='Test Property',
            address='123 Test St',
            city='Test City',
            state_or_province='TS',
            zip_code='12345',
            price=100000,
            no_of_beds=2,
            no_of_baths=2,
            square_feet_size=1000,
        )
        self.realtor = get_user_model().objects.create_user(
            email='realtor@test.com',
            password='testpass123',
            name='Test Realtor',
            phone='1234567891',
        )

        # Create realtor property
        self.realtor_property = RealtorProperty.objects.create(
            property=self.property, client=self.user, realtor=self.realtor, price=100000
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_unauthorized_request(self):
        self.client.force_authenticate(None)
        response = self.client.post('/properties/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.json(), {'detail': 'Authentication credentials were not provided.'}
        )

    def test_get_data_property_not_found(self):
        response = self.client.get(
            f'/properties/details/12?realtor_property_id={self.realtor_property.id}'
        )
        self.assertEqual(response.status_code, 404)

    def generate_unique_address(self, prefix='test_address_'):
        """Generate a unique address with random characters"""
        random_str = ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=8)  # noqa: E501
        )
        return f'{prefix}{random_str}'

    @patch.object(default_storage, 'url', side_effect=lambda x: f'/media/{x}')
    def test_get_data_property_success(self, mock_storage):
        property = Property.objects.create(
            address=self.generate_unique_address(),
            price=1,
            no_of_beds=1,
            no_of_baths=1,
            square_feet_size=1,
            additional_information='property_additional_information_1',
            image='Screenshot_2025-03-14_at_12.55.09AM.png',
        )

        PropertyMedia.objects.create(
            property_id=property, photos_list=[{'url': 'Frame_239130_p84wqlM.jpg'}]
        )

        Offer.objects.create(
            realtor_property=self.realtor_property,
            amount=4,
            description='Offer1',
            created_date='2025-04-07T09:27:56.860000Z',
        )
        Offer.objects.create(
            realtor_property=self.realtor_property,
            amount=2,
            description='Offer1 bidder 2',
            created_date='2025-04-07T10:27:56.860000Z',
        )
        Offer.objects.create(
            realtor_property=self.realtor_property,
            amount=3,
            description='Offer1 bidder 3',
            created_date='2025-04-07T11:27:56.860000Z',
        )

        Disclosure.objects.create(
            property_id=self.realtor_property,
            name='disclosure1',
        )

        comparable = Property.objects.create(
            address=self.generate_unique_address(),
            price=2,
            no_of_beds=2,
            no_of_baths=2,
            square_feet_size=2,
        )
        comparable_realtor_property = RealtorProperty.objects.create(
            property=comparable,
            client=self.user,
            realtor=self.realtor,
            price=comparable.price,
        )
        Comparable.objects.create(
            from_property=self.realtor_property, to_property=comparable_realtor_property
        )

        response = self.client.get(
            f'/properties/details/{property.id}?realtor_property_id={self.realtor_property.id}'
        )
        self.assertEqual(response.status_code, 200)

        response_data = response.json().get('data')

        self.assertEqual(
            response_data['image'], 'Screenshot_2025-03-14_at_12.55.09AM.png'
        )
        self.assertEqual(len(response_data['photos_list']), 1)
        self.assertEqual(
            response_data['photos_list'][0]['url'], 'Frame_239130_p84wqlM.jpg'
        )
        self.assertEqual(response_data['address'], property.address)
        self.assertEqual(response_data['price'], 1)
        self.assertEqual(response_data['bedsCount'], 1)
        self.assertEqual(response_data['bathsCount'], 1)
        self.assertEqual(response_data['squareFeet'], 1)
        self.assertEqual(response_data['zillowIntegration'], False)
        self.assertEqual(
            response_data['additional_information'], 'property_additional_information_1'
        )

        self.assertEqual(len(response_data['offers']), 3)
        self.assertEqual(response_data['offers'][0]['amount'], 4)
        self.assertEqual(response_data['offers'][1]['amount'], 2)
        self.assertEqual(response_data['offers'][2]['amount'], 3)

        self.assertEqual(len(response_data['disclosure']), 1)
        self.assertEqual(response_data['disclosure'][0]['name'], 'disclosure1')

        self.assertEqual(len(response_data['comparables']), 1)
        self.assertEqual(response_data['comparables'][0]['address'], comparable.address)

        self.assertEqual(response_data['offerGraph']['askedPrice'], 1)
        self.assertEqual(response_data['offerGraph']['firstOffer'], 4)
        self.assertEqual(response_data['offerGraph']['secondOffer'], 2)


class SendMessageViewTests(TestCase):
    permission_classes = [IsAuthenticated]

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='testpass123',
            name='Test User',
            phone='1234567890',
            user_type='user',
        )
        self.realtor = CustomUser.objects.create_user(
            email='testrealtor@example.com',
            password='testpass123',
            name='Test Realtor',
            phone='1111111111',
            user_type='realtor',
        )
        self.property = Property.objects.create(
            name='Test Property',
            address='123 Test Street',
            price=500000,
            square_feet_size=1500,
        )
        self.realtor_property = RealtorProperty.objects.create(
            property=self.property,
            realtor=self.realtor,
            client=self.user,
        )
        self.url = '/properties/chat'
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_unauthorized_request(self):
        self.client.force_authenticate(None)

        response = self.client.get('/properties/chat')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.json(), {'detail': 'Authentication credentials were not provided.'}
        )

    def test_send_message_success(self):
        self.client.login(name='testuser', password='testpass123')
        payload = {
            'realtor_property_id': self.realtor_property.id,
            'message': 'Is this property still available?',
        }
        response = self.client.post(self.url, data=payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'Message sent successfully.')

        self.assertIn('id', response.data['data'])
        self.assertEqual(response.data['data']['user'], self.user.id)
        self.assertEqual(response.data['data']['property'], self.property.id)
        self.assertEqual(
            response.data['data']['message'], 'Is this property still available?'
        )

    def test_send_message_property_not_found(self):
        self.client.login(name='testuser', password='testpass123')
        payload = {
            'realtor_property_id': 9999,
            'message': 'Is this property still available?',
        }
        response = self.client.post(self.url, data=payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Property not found.')
        self.assertEqual(response.data['data'], {})

    def test_send_message_invalid_data(self):
        self.client.login(name='testuser', password='testpass123')
        payload = {'realtor_property_id': '', 'message': ''}
        response = self.client.post(self.url, data=payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Request is invalid')
        self.assertEqual(response.data['code'], 'request_invalid')
        self.assertDictEqual(
            response.data['data'],
            {
                'realtor_property_id': ['A valid integer is required.'],
                'message': ['This field may not be blank.'],
            },
        )

    def test_send_message_unauthenticated(self):
        self.client.force_authenticate(None)
        response = self.client.get('/properties/chat').json()
        self.assertDictEqual(
            response, {'detail': 'Authentication credentials were not provided.'}
        )


class ReceiveMessageViewTests(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='testpass123',
            name='Test User',
            phone='1234567890',
            user_type='user',
        )
        self.realtor = CustomUser.objects.create_user(
            email='testrealtor@example.com',
            password='testpass123',
            name='Test Realtor',
            phone='1111111111',
            user_type='realtor',
        )
        self.property = Property.objects.create(
            name='Test Property',
            address='123 Test Street',
            price=500000,
            square_feet_size=1500,
        )
        self.realtor_property = RealtorProperty.objects.create(
            property=self.property,
            realtor=self.realtor,
            client=self.user,
        )
        self.url = f'/properties/{self.property.id}/chat'
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_receive_message_success(self):
        Chat.objects.create(
            property=self.realtor_property, user=self.user, message='First message'
        )
        Chat.objects.create(
            property=self.realtor_property, user=self.user, message='Second message'
        )

        response = self.client.get(
            f'{self.url}?realtor_property_id={self.realtor_property.id}'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'Message sent successfully.')
        self.assertIn('messages', response.data['data'])
        self.assertIn('page', response.data['data'])
        self.assertIn('has_next', response.data['data'])
        self.assertIn('total', response.data['data'])
        self.assertEqual(response.data['data']['total'], 2)

    def test_receive_message_property_not_found(self):
        invalid_url = '/properties/9999/chat'
        response = self.client.get(invalid_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Property not found.')
        self.assertEqual(response.data['code'], 'not_found')
        self.assertEqual(response.data['data'], {})

    def test_receive_message_unauthenticated(self):
        self.client.force_authenticate(None)
        response = self.client.get(f'/properties/{self.property.id}/chat')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.json(), {'detail': 'Authentication credentials were not provided.'}
        )

    def test_receive_message_with_pagination(self):
        for i in range(25):
            Chat.objects.create(
                property=self.realtor_property,
                user=self.user,
                message=f'Message {i + 1}',
            )

        response = self.client.get(
            f'{self.url}?limit=10&offset=0&realtor_property_id={self.realtor_property.id}'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(len(response.data['data']['messages']), 10)
        self.assertTrue(response.data['data']['has_next'])
        self.assertEqual(response.data['data']['total'], 25)

        response_next = self.client.get(
            f'{self.url}?limit=10&offset=10&realtor_property_id={self.realtor_property.id}'
        )
        self.assertEqual(response_next.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_next.data['data']['messages']), 10)

        response_last = self.client.get(
            f'{self.url}?limit=10&offset=20&realtor_property_id={self.realtor_property.id}'
        )
        self.assertEqual(response_last.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_last.data['data']['messages']), 5)
        self.assertFalse(response_last.data['data']['has_next'])
