# Standard library imports
import time

from chat.models import Chat
from chat.serializers import ChatSerializer
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import (
    BooleanField,
    Case,
    CharField,
    F,
    OuterRef,
    PositiveIntegerField,
    Prefetch,
    Q,
    Subquery,
    Value,
    When,
)

# Local application imports
from properties.models import ClientProperty, Offer, Property, RealtorProperty
from properties.serializers import (
    OfferCreateSerializer,
    PollNewMessageSerializer,
    PropertyDetailsSerializer,
    PropertyGetSerializer,
    PropertyMedia,
    PropertyPostSerializer,
    PropertySerializer,
    ReceiveMessageSerializer,
    SendMessageSerializer,
)

# Third-party imports
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from user_management.models import RealtorClient
from user_management.utils import IsRealtor


User = get_user_model()


class PropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        request_serializer = PropertyGetSerializer(data=request.GET)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_data = request_serializer.validated_data
        request_search = request_data.get('search')
        request_sort = request_data.get('sort')
        request_page = request_data.get('page', 1)
        request_limit = request_data.get('limit', 10)
        client_id = request_data.get('user_id')

        properties = Property.objects.all().order_by('-id')

        if request.user.user_type == 'realtor':
            if not client_id:
                return Response(
                    {
                        'success': False,
                        'message': 'Missing user_id for client.',
                        'code': 'client_id_missing',
                        'status': status.HTTP_400_BAD_REQUEST,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            realtor_properties_qs = RealtorProperty.objects.filter(
                realtor=request.user, client_id=client_id
            )
            realtor_property_map = {
                rp.property_id: rp.id for rp in realtor_properties_qs
            }

            properties = properties.filter(id__in=realtor_property_map.keys())

            # Attach the `realtor_property_id` to each property manually
            for prop in properties:
                prop.realtor_property_id = realtor_property_map.get(prop.id)

        elif request.user.user_type == 'user':
            client_properties_qs = ClientProperty.objects.filter(
                client=request.user
            ).select_related('realtor_property')

            client_property_map = {
                cp.realtor_property.property_id: cp.realtor_property_id
                for cp in client_properties_qs
            }

            properties = properties.filter(id__in=client_property_map.keys())

            for prop in properties:
                prop.realtor_property_id = client_property_map.get(prop.id)

        if request_search:
            properties = properties.filter(
                Q(name__icontains=request_search) | Q(address__icontains=request_search)
            )

        if request_sort == 'ASC':
            properties = properties.order_by('price')
        if request_sort == 'DESC':
            properties = properties.order_by('-price')

        total_properties = properties.count()

        properties_paginator = Paginator(properties, request_limit)
        properties_page = properties_paginator.get_page(request_page)

        properties = properties_page.object_list

        response_data = PropertySerializer(properties, many=True).data

        return Response(
            {
                'success': True,
                'message': 'Properties fetched successfully.',
                'status': status.HTTP_200_OK,
                'data': {
                    'list': response_data,
                    'page': properties_page.number,
                    'has_next': properties_page.has_next(),
                    'total': total_properties,
                },
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        request_serializer = PropertyPostSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user_type = getattr(request.user, 'user_type', None)
            client = None
            realtor = None

            if user_type == 'realtor':
                client_id = request.data.get('user_id')
                if not client_id:
                    return Response(
                        {
                            'success': False,
                            'message': 'Missing user_id for client.',
                            'code': 'client_id_missing',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                try:
                    client = User.objects.get(id=client_id)
                    realtor = request.user
                except User.DoesNotExist:
                    return Response(
                        {
                            'success': False,
                            'message': 'Invalid client user_id provided.',
                            'code': 'client_not_found',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            elif user_type == 'user':
                realtor = RealtorClient.objects.filter(client=request.user).first()
                realtor_id = realtor.realtor_id
                if not realtor_id:
                    return Response(
                        {
                            'success': False,
                            'message': 'Missing realtor_id.',
                            'code': 'realtor_id_missing',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                try:
                    realtor = User.objects.get(id=realtor_id)
                    client = request.user
                except User.DoesNotExist:
                    return Response(
                        {
                            'success': False,
                            'message': 'Invalid realtor_id provided.',
                            'code': 'realtor_not_found',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            property = request_serializer.save()

            realtor_property = RealtorProperty.objects.create(
                property=property,
                realtor=realtor,
                client=client,
                price=request.data.get('price', 0),
            )
            ClientProperty.objects.create(
                realtor_property=realtor_property, client=client
            )
        except IntegrityError as e:
            if 'UNIQUE constraint failed' in str(
                e
            ) and 'properties_property.address' in str(e):
                return Response(
                    {
                        'success': False,
                        'message': 'Address must be unique.',
                        'code': 'unique_constraint_failed',
                        'status': status.HTTP_400_BAD_REQUEST,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                raise  # Re-raise if it's a different integrity error

        return Response(
            {
                'success': True,
                'message': 'Property created successfully.',
                'status': status.HTTP_200_OK,
                'data': {'id': property.id},
            },
            status=status.HTTP_200_OK,
        )


class PropertyDetailsView(APIView):
    def get(self, request, property_id):
        _property = (
            Property.objects.filter(id=property_id)
            .annotate(
                first_offer=Subquery(
                    Offer.objects.filter(property_id__id=OuterRef('id'))
                    .order_by('created_date')
                    .values('amount')[:1],
                    output_field=PositiveIntegerField(),
                ),
                second_offer=Subquery(
                    Offer.objects.filter(property_id__id=OuterRef('id'))
                    .order_by('created_date')
                    .values('amount')[1:2],
                    output_field=PositiveIntegerField(),
                ),
                last_offer=Subquery(
                    Offer.objects.filter(property_id__id=OuterRef('id')).values(
                        'amount'
                    )[:1],
                    output_field=PositiveIntegerField(),
                ),
                zillow_integration=Case(
                    When(property_details__zillow_url__isnull=False, then=Value(True)),
                    default=Value(False),
                    output_field=BooleanField(),
                ),
            )
            .prefetch_related('property_offers')
            .prefetch_related('property_disclosures')
            .prefetch_related(
                Prefetch(
                    'comparables',
                    queryset=Property.objects.annotate(
                        closing_price=Subquery(
                            Offer.objects.filter(property_id__id=OuterRef('id')).values(
                                'amount'
                            )[:1],
                            output_field=PositiveIntegerField(),
                        ),
                        offer_image=Subquery(
                            PropertyMedia.objects.filter(
                                property_id__id=OuterRef('id')
                            ).values('image')[:1],
                            output_field=CharField(),
                        ),
                        amount_per_sqr_feet=F('price') / F('square_feet_size'),
                    ),
                    to_attr='comparables_with_last_offer',
                )
            )
            .first()
        )

        if not _property:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        data = PropertyDetailsSerializer(_property).data

        return Response(
            {
                'success': True,
                'message': 'Property details fetched successfully.',
                'status': status.HTTP_200_OK,
                'data': data,
            },
            status=status.HTTP_200_OK,
        )


class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request_serializer = SendMessageSerializer(data=request.data)

        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            property = RealtorProperty.objects.get(
                id=request_serializer.validated_data['realtor_property_id']
            )
        except RealtorProperty.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'not_found',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        message = Chat.objects.create(
            user=self.request.user,
            property=property,
            message=request_serializer.validated_data['message'],
        )

        message_data = ChatSerializer(message).data

        return Response(
            {
                'success': True,
                'message': 'Message sent successfully.',
                'status': status.HTTP_200_OK,
                'data': message_data,
            },
            status=status.HTTP_200_OK,
        )


class ReceiveMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, property_id):
        try:
            Property.objects.get(id=property_id)
        except Property.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'not_found',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        limit = int(request.query_params.get('limit', 20))
        offset = int(request.query_params.get('offset', 0))
        realtor_property_id = request.query_params.get('realtor_property_id', '')

        messages = Chat.objects.filter(property_id=realtor_property_id).order_by(
            'timestamp'
        )

        paginator = Paginator(messages, limit)

        messages_page = paginator.get_page(offset // limit + 1)

        response_data = {
            'messages': messages_page,
            'page': messages_page.number,
            'has_next': messages_page.has_next(),
            'total': paginator.count,
        }

        serializer = ReceiveMessageSerializer(response_data)

        return Response(
            {
                'success': True,
                'message': 'Message sent successfully.',
                'status': status.HTTP_200_OK,
                'data': serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class PollNewMessagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, property_id):
        try:
            Property.objects.get(id=property_id)
        except Property.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'not_found',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        last_message_id = int(request.query_params.get('last_message_id', 0))
        realtor_property_id = request.query_params.get('realtor_property_id', '')

        timeout = 5
        poll_interval = 1
        waited = 0

        while waited < timeout:
            new_messages = Chat.objects.filter(
                property_id=realtor_property_id, id__gt=last_message_id
            ).order_by('timestamp')

            if new_messages.exists():
                response_data = {
                    'messages': new_messages,
                }

                serializer = PollNewMessageSerializer(response_data)

                return Response(
                    {
                        'success': True,
                        'message': 'New messages found.',
                        'status': status.HTTP_200_OK,
                        'data': serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )

            time.sleep(poll_interval)
            waited += poll_interval

        return Response(
            {
                'success': True,
                'message': 'No new messages.',
                'status': status.HTTP_200_OK,
                'data': [],
            },
            status=status.HTTP_200_OK,
        )


class CreateNewOfferView(APIView):
    permission_classes = [IsRealtor]

    def post(self, request):
        serializer = OfferCreateSerializer(
            data=request.data, context={'request': request}
        )

        if not serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        offer = serializer.save()
        return Response(
            {
                'success': True,
                'message': 'Offer created successfully.',
                'offer_id': offer.id,
            },
            status=status.HTTP_201_CREATED,
        )
