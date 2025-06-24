# Standard library imports
import time

from chat.models import Chat
from chat.serializers import ChatSerializer
from django.core.paginator import Paginator
from django.db.models import (
    Avg,
    BooleanField,
    Case,
    CharField,
    ExpressionWrapper,
    F,
    FloatField,
    OuterRef,
    PositiveIntegerField,
    Prefetch,
    Q,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Greatest
from django.utils import timezone
from django.utils.dateparse import parse_datetime

# Local application imports
from properties.models import (
    ClientProperty,
    Comparable,
    Offer,
    Property,
    RealtorProperty,
)
from properties.serializers import (
    ComparableDetailSerializer,
    ComparableSerializer,
    DisclosureSerializer,
    OfferCreateSerializer,
    PollNewMessageSerializer,
    PropertyDetailsSerializer,
    PropertyGetSerializer,
    PropertyMedia,
    PropertyPostSerializer,
    PropertySerializer,
    RatingSerializer,
    ReceiveMessageSerializer,
    SendMessageSerializer,
    TourStatusSerializer,
)

# Third-party imports
from rest_framework import permissions, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from user_management.models import ClientFamily, CustomUser, RealtorClient
from user_management.utils import IsRealtor


class PropertyViewingStateMixin:
    def update_property_viewing_state(self, property_obj, request):
        """Update the property viewing state based on user type."""
        if (
            request.user.user_type == 'realtor'
            and property_obj.is_property_viewed_by_client is True
        ):
            property_obj.is_property_viewed_by_client = None
            property_obj.save()
        elif (
            request.user.user_type == 'user'
            and property_obj.is_property_viewed_by_client is False
        ):
            property_obj.is_property_viewed_by_client = None
            property_obj.save()

    def get_properties_for_user(self, request, client_id=None):
        """Get properties based on user type and role."""
        properties = Property.objects.all().order_by('-id')

        if request.user.user_type == 'realtor':
            if not client_id:
                return None, Response(
                    {
                        'success': False,
                        'message': 'Missing user_id for client.',
                        'code': 'client_id_missing',
                        'status': status.HTTP_400_BAD_REQUEST,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Get the parent client user object
            try:
                parent_client = CustomUser.objects.get(id=client_id)
            except CustomUser.DoesNotExist:
                return None, Response(
                    {
                        'success': False,
                        'message': 'Client not found.',
                        'code': 'client_not_found',
                        'status': status.HTTP_404_NOT_FOUND,
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Build Q objects - include parent's properties
            q_objects = Q(client=parent_client)

            # Include all family members' properties under this parent
            family_members = ClientFamily.objects.filter(
                parent=parent_client
            ).values_list('member', flat=True)

            if family_members:
                q_objects |= Q(client__in=family_members)

            # Filter RealtorProperty with parent + family members
            realtor_properties_qs = (
                RealtorProperty.objects.filter(
                    realtor=request.user, is_added_for_comparable=False
                )
                .filter(q_objects)
                .select_related('property')
            )

            realtor_property_map = {
                rp.property_id: rp.id for rp in realtor_properties_qs
            }

            properties = properties.filter(id__in=realtor_property_map.keys())

            for prop in properties:
                prop.realtor_property_id = realtor_property_map.get(prop.id)

        elif request.user.user_type == 'user':
            client = request.user
            q_objects = Q(client=client)
            client_family = (
                ClientFamily.objects.filter(member=client)
                .select_related('parent')
                .first()
            )

            if client_family:
                # Current user is a MEMBER
                parent = client_family.parent

                # Include parent's properties
                q_objects |= Q(client=parent)

                # Include all other family members' properties (siblings)
                all_family_members = (
                    ClientFamily.objects.filter(parent=parent)
                    .exclude(member=client)
                    .values_list('member', flat=True)
                )

                if all_family_members:
                    q_objects |= Q(client__in=all_family_members)
            else:
                family_members = ClientFamily.objects.filter(parent=client).values_list(
                    'member', flat=True
                )

                if family_members:
                    q_objects |= Q(client__in=family_members)

            # Get all relevant client properties
            client_properties_qs = ClientProperty.objects.filter(
                q_objects, is_added_for_comparable=False
            ).select_related('realtor_property', 'realtor_property__property')

            client_property_map = {
                cp.realtor_property.property_id: cp.realtor_property_id
                for cp in client_properties_qs
            }

            properties = properties.filter(id__in=client_property_map.keys())

            for prop in properties:
                prop.realtor_property_id = client_property_map.get(prop.id)

        return properties, None


class PropertyView(PropertyViewingStateMixin, APIView):
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
        request_limit = request_data.get('limit', 12)
        client_id = request_data.get('user_id')

        properties, error = self.get_properties_for_user(request, client_id)
        if error:
            return error

        properties = properties.prefetch_related(
            'realtor_properties__offers',
            'realtor_properties__property_disclosures__files',
            'property_details',
            'property_media',
        )

        if request_search:
            properties = properties.filter(
                Q(name__icontains=request_search) | Q(address__icontains=request_search)
            )

        if request_sort is not None:
            sort_field, sort_order = request_sort.split('_')
            order_prefix = '-' if sort_order == 'DESC' else ''

            if sort_field == 'date':
                properties = properties.order_by(f'{order_prefix}created_at')
            elif sort_field == 'price':
                properties = properties.annotate(
                    last_offer_amount=Subquery(
                        RealtorProperty.objects.filter(property=OuterRef('pk'))
                        .values('offers__amount')
                        .order_by('-offers__created_date')[:1]
                    )
                ).order_by(f'{order_prefix}last_offer_amount')
            elif sort_field == 'activity':
                properties = properties.annotate(
                    last_activity=Greatest(
                        'created_at',
                        'updated_at',
                        Subquery(
                            RealtorProperty.objects.filter(property=OuterRef('pk'))
                            .values('offers__created_date')
                            .order_by('-offers__created_date')[:1]
                        ),
                        Subquery(
                            RealtorProperty.objects.filter(
                                property=OuterRef('pk')
                            ).values('timestamp')[:1]
                        ),
                        Subquery(
                            ClientProperty.objects.filter(
                                realtor_property__property=OuterRef('pk')
                            ).values('timestamp')[:1]
                        ),
                    )
                ).order_by(f'{order_prefix}last_activity')
            elif sort_field == 'rating':
                properties = properties.annotate(
                    avg_rating=Avg('realtor_properties__property_rating')
                ).order_by(f'{order_prefix}avg_rating')

        total_properties = properties.count()

        properties_paginator = Paginator(properties, request_limit)
        properties_page = properties_paginator.get_page(request_page)

        properties = properties_page.object_list

        response_data = PropertySerializer(
            properties, many=True, context={'request': request}
        ).data

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
                    client = CustomUser.objects.get(id=client_id)
                    realtor = request.user
                except CustomUser.DoesNotExist:
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
                realtor_relation = RealtorClient.objects.filter(
                    client=request.user
                ).first()
                if not realtor_relation:
                    return Response(
                        {
                            'success': False,
                            'message': 'Realtor-client relationship not found.',
                            'code': 'realtor_client_missing',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                realtor_id = realtor_relation.realtor_id
                try:
                    realtor = CustomUser.objects.get(id=realtor_id)
                    client = request.user
                except CustomUser.DoesNotExist:
                    return Response(
                        {
                            'success': False,
                            'message': 'Invalid realtor_id provided.',
                            'code': 'realtor_not_found',
                            'status': status.HTTP_400_BAD_REQUEST,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            listing_id = request.data.get('listing_id')
            property = None

            if listing_id:
                property = Property.objects.filter(listing_id=listing_id).first()
                if property:
                    realtor_property_qs = RealtorProperty.objects.filter(
                        property=property
                    )

                    if realtor_property_qs.filter(
                        realtor=realtor, client=client, is_added_for_comparable=False
                    ).exists():
                        return Response(
                            {
                                'success': False,
                                'message': 'Property already added',
                                'code': 'duplicate_entry',
                                'status': status.HTTP_400_BAD_REQUEST,
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    else:
                        # Update viewing state for existing property
                        if user_type == 'realtor':
                            property.is_property_viewed_by_client = False
                        else:
                            property.is_property_viewed_by_client = True
                        property.save()
                else:
                    # Create new property with appropriate viewing state
                    if user_type == 'realtor':
                        property = request_serializer.save(
                            is_property_viewed_by_client=False
                        )
                    else:
                        property = request_serializer.save(
                            is_property_viewed_by_client=True
                        )

                    photos_list = request.data.get('photosList', [])
                    if photos_list and isinstance(photos_list, list):
                        PropertyMedia.objects.create(
                            property_id=property, photos_list=photos_list
                        )

                realtor_property = RealtorProperty.objects.filter(
                    property=property,
                    client=client,
                    realtor=realtor,
                ).first()

                if realtor_property:
                    realtor_property.is_added_for_comparable = False
                    realtor_property.save()
                else:
                    realtor_property = RealtorProperty.objects.create(
                        property=property,
                        realtor=realtor,
                        client=client,
                        price=request.data.get('price', 0),
                    )

                client_property = ClientProperty.objects.filter(
                    realtor_property=realtor_property,
                    client=client,
                ).first()

                if client_property:
                    client_property.is_added_for_comparable = False
                    client_property.save()
                else:
                    ClientProperty.objects.create(
                        realtor_property=realtor_property, client=client
                    )

                self.request.user.last_activity = timezone.now()
                self.request.user.save()

        except Exception as e:
            return Response(
                {
                    'success': False,
                    'message': 'An unexpected error occurred.',
                    'error': str(e),
                    'code': 'unexpected_error',
                    'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                'success': True,
                'message': 'Property created successfully.',
                'status': status.HTTP_200_OK,
                'data': {'id': property.id},
            },
            status=status.HTTP_200_OK,
        )

    def put(self, request, pk=None):
        # Check if property_id is provided
        if not pk:
            return Response(
                {
                    'success': False,
                    'message': 'Property ID is required for update.',
                    'code': 'property_id_required',
                    'status': status.HTTP_400_BAD_REQUEST,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify user is a realtor
        if getattr(request.user, 'user_type', None) != 'realtor':
            return Response(
                {
                    'success': False,
                    'message': 'Only realtors can update properties.',
                    'code': 'realtor_required',
                    'status': status.HTTP_403_FORBIDDEN,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            # Get the property to update
            property = Property.objects.get(id=pk)

            # Verify the realtor has permission to update this property
            if not RealtorProperty.objects.filter(
                property=property, realtor=request.user
            ).exists():
                return Response(
                    {
                        'success': False,
                        'message': 'You do not have permission to update property.',
                        'code': 'permission_denied',
                        'status': status.HTTP_403_FORBIDDEN,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Validate the request data
            request_serializer = PropertyPostSerializer(
                property,
                data=request.data,
                partial=True,  # Allow partial updates
            )

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

            # Update the property
            updated_property = request_serializer.save()

            # Handle deadline_datetime if provided
            if 'deadline_datetime' in request.data:
                deadline_datetime = request.data['deadline_datetime']
                if deadline_datetime:
                    try:
                        parsed_datetime = parse_datetime(deadline_datetime)
                        if parsed_datetime:
                            updated_property.deadline_datetime = parsed_datetime
                            updated_property.save()
                        else:
                            return Response(
                                {
                                    'success': False,
                                    'message': 'Invalid deadline_datetime format.',
                                    'code': 'invalid_datetime',
                                    'status': status.HTTP_400_BAD_REQUEST,
                                },
                                status=status.HTTP_400_BAD_REQUEST,
                            )
                    except (ValueError, TypeError):
                        return Response(
                            {
                                'success': False,
                                'message': 'Invalid deadline_datetime format.',
                                'code': 'invalid_datetime',
                                'status': status.HTTP_400_BAD_REQUEST,
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )

            # Handle is_deadline_checked if provided
            if 'is_deadline_checked' in request.data:
                updated_property.is_deadline_checked = request.data[
                    'is_deadline_checked'
                ]
                updated_property.save()

            # Handle note if provided
            if 'note' in request.data:
                updated_property.note = request.data['note']
                updated_property.save()

            # Update last activity
            request.user.last_activity = timezone.now()
            request.user.save()

            return Response(
                {
                    'success': True,
                    'message': 'Property updated successfully.',
                    'status': status.HTTP_200_OK,
                    'data': PropertySerializer(
                        updated_property, context={'request': request}
                    ).data,
                },
                status=status.HTTP_200_OK,
            )

        except Property.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'property_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {
                    'success': False,
                    'message': 'An unexpected error occurred.',
                    'error': str(e),
                    'code': 'unexpected_error',
                    'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PropertyDetailsView(PropertyViewingStateMixin, APIView):
    def get(self, request, property_id):
        realtor_property_id = request.query_params.get('realtor_property_id')

        _property = (
            Property.objects.filter(id=property_id)
            .annotate(
                first_offer=Subquery(
                    Offer.objects.filter(realtor_property_id=realtor_property_id)
                    .order_by('created_date')
                    .values('amount')[:1],
                    output_field=PositiveIntegerField(),
                ),
                second_offer=Subquery(
                    Offer.objects.filter(realtor_property_id=realtor_property_id)
                    .order_by('created_date')
                    .values('amount')[1:2],
                    output_field=PositiveIntegerField(),
                ),
                last_offer=Subquery(
                    Offer.objects.filter(
                        realtor_property_id=realtor_property_id
                    ).values('amount')[:1],
                    output_field=PositiveIntegerField(),
                ),
                zillow_integration=Case(
                    When(property_details__zillow_url__isnull=False, then=Value(True)),
                    default=Value(False),
                    output_field=BooleanField(),
                ),
                property_rating=Subquery(  # Add this annotation
                    RealtorProperty.objects.filter(
                        property_id=property_id, id=realtor_property_id
                    ).values('property_rating')[:1],
                    output_field=FloatField(),
                ),
            )
            .prefetch_related('realtor_properties__offers')
            .prefetch_related(
                'realtor_properties__from_property_comparables__to_property'
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

        self.update_property_viewing_state(_property, request)

        data = PropertyDetailsSerializer(
            _property,
            context={'realtor_property_id': realtor_property_id, 'request': request},
        ).data

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

        is_chat_viewed_by_client = True
        if request.user.user_type == 'realtor':
            is_chat_viewed_by_client = False

        message = Chat.objects.create(
            user=self.request.user,
            property=property,
            message=request_serializer.validated_data['message'],
            is_chat_viewed_by_client=is_chat_viewed_by_client,
        )

        self.request.user.last_activity = timezone.now()
        self.request.user.save()

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

        if request.user.user_type == 'realtor':
            messages.filter(
                is_chat_viewed_by_client=True, user__user_type='user'
            ).update(is_chat_viewed_by_client=None)
        else:
            messages.filter(
                is_chat_viewed_by_client=False, user__user_type='realtor'
            ).update(is_chat_viewed_by_client=None)

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


class DisclosureView(APIView):
    permission_classes = [IsRealtor]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, pk):
        if not request.FILES and not request.data.get('url'):
            return Response(
                {
                    'success': False,
                    'message': 'File upload or url is required.',
                    'code': 'file_upload_or_url_required',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        request_serializer = DisclosureSerializer(
            data=request.data, context={'request': request}
        )
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
        property = RealtorProperty.objects.filter(
            id=request.data.get('realtor_property_id')
        ).first()
        if not property:
            return Response(
                {
                    'success': False,
                    'message': 'Property not found.',
                    'code': 'property_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        disclosure = request_serializer.save(property_id=property)
        return Response(
            {
                'success': True,
                'message': 'Disclosure added successfully.',
                'status': status.HTTP_200_OK,
                'data': DisclosureSerializer(disclosure).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ComparableView(APIView):
    permission_classes = [IsRealtor]

    def post(self, request, pk):
        request_serializer = ComparableSerializer(data=request.data)
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

        from_realtor_property = RealtorProperty.objects.filter(
            id=request_serializer.validated_data.get('realtor_property_id')
        ).first()
        if not from_realtor_property:
            return Response(
                {
                    'success': False,
                    'message': 'From Property not found.',
                    'code': 'property_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing_link_comparable = Comparable.objects.filter(
            from_property=from_realtor_property, is_link_only=True
        ).first()

        is_link_only = request_serializer.validated_data.get('is_link_only', False)

        if is_link_only:
            if existing_link_comparable:
                return Response(
                    {
                        'success': False,
                        'message': 'Only one link allowed per property.',
                        'code': 'link_comparable_exists',
                        'status': status.HTTP_400_BAD_REQUEST,
                        'data': {},
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # For link-only comparables, we don't need to create a property
            comparable = Comparable.objects.create(
                from_property=from_realtor_property,
                url=request_serializer.validated_data.get('url'),
                additional_info=request_serializer.validated_data.get(
                    'additional_info'
                ),
                is_link_only=True,
            )
            return Response(
                {
                    'success': True,
                    'message': 'Link added successfully.',
                    'status': status.HTTP_201_CREATED,
                    'data': ComparableDetailSerializer(comparable).data,
                },
                status=status.HTTP_201_CREATED,
            )

        if existing_link_comparable:
            return Response(
                {
                    'success': False,
                    'message': 'Cannot add address-based comparables',
                    'code': 'link_comparable_exists',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        address_data = request_serializer.validated_data.get('address')
        to_property = Property.objects.filter(
            listing_id=address_data['listing_id']
        ).first()
        if not to_property:
            to_property = request_serializer.save()

        client = CustomUser.objects.filter(
            id=request_serializer.validated_data.get('client_id')
        ).first()
        if not client:
            return Response(
                {
                    'success': False,
                    'message': 'Client not found.',
                    'code': 'client_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        to_realtor_property = RealtorProperty.objects.filter(
            property=to_property,
            client=client,
            realtor=request.user,
        ).first()
        if not to_realtor_property:
            to_realtor_property = RealtorProperty.objects.create(
                is_added_for_comparable=True,
                property=to_property,
                realtor=request.user,
                client=client,
                price=address_data['price'],
            )
            ClientProperty.objects.create(
                realtor_property=to_realtor_property,
                client=client,
                is_added_for_comparable=True,
            )

        if to_realtor_property.id == from_realtor_property.id:
            return Response(
                {
                    'success': False,
                    'message': 'Cannot compare a property with itself.',
                    'code': 'self_comparison',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing_comparable = Comparable.objects.filter(
            from_property=from_realtor_property, to_property=to_realtor_property
        ).first()
        if existing_comparable:
            return Response(
                {
                    'success': False,
                    'message': 'Comparable already exist.',
                    'code': 'comparable_exist',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        comparable = Comparable.objects.create(
            to_property=to_realtor_property,
            from_property=from_realtor_property,
            url=request_serializer.validated_data.get('url'),
            additional_info=request_serializer.validated_data.get('additional_info'),
            is_link_only=False,
        )

        comparable = (
            Comparable.objects.filter(
                to_property=to_realtor_property, from_property=from_realtor_property
            )
            .prefetch_related(
                Prefetch(
                    'to_property',
                    queryset=RealtorProperty.objects.select_related(
                        'property'
                    ).annotate(
                        closing_price=Subquery(
                            Offer.objects.filter(
                                realtor_property_id=OuterRef('id')
                            ).values('amount')[:1],
                            output_field=PositiveIntegerField(),
                        ),
                        offer_image=Subquery(
                            PropertyMedia.objects.filter(
                                property_id__id=OuterRef('property_id')
                            ).values('photos_list')[:1],
                            output_field=CharField(),
                        ),
                        amount_per_sqr_feet=Case(
                            When(
                                Q(property__square_feet_size__isnull=True)
                                | Q(property__square_feet_size=0)
                                | Q(property__square_feet_size='0'),
                                then=Value(None),
                            ),
                            default=ExpressionWrapper(
                                F('property__price') / F('property__square_feet_size'),
                                output_field=FloatField(),
                            ),
                        ),
                    ),
                )
            )
            .first()
        )

        return Response(
            {
                'success': True,
                'message': 'Comparable added successfully.',
                'status': status.HTTP_200_OK,
                'data': ComparableDetailSerializer(comparable).data,
            },
            status=status.HTTP_201_CREATED,
        )

    def delete(self, request, pk, comparable_id):
        try:
            comparable = Comparable.objects.get(id=comparable_id)

            if comparable.from_property.realtor != request.user:
                return Response(
                    {
                        'success': False,
                        'message': 'You do not have permission to \
                        delete this comparable.',
                        'code': 'permission_denied',
                        'status': status.HTTP_403_FORBIDDEN,
                        'data': {},
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            comparable.delete()
            return Response(
                {
                    'success': True,
                    'message': 'Comparable deleted successfully.',
                    'status': status.HTTP_200_OK,
                    'data': {},
                },
                status=status.HTTP_200_OK,
            )
        except Comparable.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Comparable not found.',
                    'code': 'comparable_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
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


class OfferView(APIView):
    permission_classes = [IsRealtor]

    def post(self, request):
        """Handle creating new offers"""
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

    def delete(self, request, property_id, offer_id):
        """Handle deleting existing offers delete"""
        try:
            # Get the offer and verify it belongs to the requesting realtor and property
            offer = Offer.objects.get(
                id=offer_id,
                realtor_property__property_id=property_id,
                realtor_property__realtor=request.user,
            )

            offer.delete()

            return Response(
                {
                    'success': True,
                    'message': 'Offer deleted successfully.',
                    'status': status.HTTP_200_OK,
                    'data': {},
                },
                status=status.HTTP_200_OK,
            )

        except Offer.DoesNotExist:
            return Response(
                {
                    'success': False,
                    'message': 'Offer not found or you do not have permission to delete it.',  # noqa: E501
                    'code': 'offer_not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )


class UpdateRatingAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk):
        try:
            rating = request.data.get('rating')

            if rating is None:
                return Response(
                    {'error': 'rating is required'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            realtor_property = RealtorProperty.objects.get(id=pk)

            if request.user.id not in [
                realtor_property.client_id,
                realtor_property.realtor_id,
            ]:
                return Response(
                    {'error': 'Unauthorized to rate this property'},
                    status=status.HTTP_403_FORBIDDEN,
                )

            serializer = RatingSerializer(
                realtor_property, data={'property_rating': rating}, partial=True
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)

        except RealtorProperty.DoesNotExist:
            return Response(
                {'error': 'Property relationship not found'},
                status=status.HTTP_404_NOT_FOUND,
            )


class UpdateTourStatusAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk):
        try:
            is_toured = request.data.get('is_property_toured')

            if is_toured is None:
                return Response(
                    {'error': 'is_property_toured is required'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            realtor_property = RealtorProperty.objects.get(id=pk)

            # Check if the authenticated user is the CLIENT (not realtor)
            if request.user.id != realtor_property.client_id:
                return Response(
                    {'error': 'Only the client can update the tour status'},
                    status=status.HTTP_403_FORBIDDEN,
                )

            serializer = TourStatusSerializer(
                realtor_property, data={'is_property_toured': is_toured}, partial=True
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)

        except RealtorProperty.DoesNotExist:
            return Response(
                {'error': 'Property relationship not found'},
                status=status.HTTP_404_NOT_FOUND,
            )
