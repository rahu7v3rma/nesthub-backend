# Third-party imports
# Local application imports
from chat.models import Chat
from django.contrib.auth import get_user_model
from properties.models import (
    Comparable,
    Disclosure,
    DisclosureFile,
    Offer,
    Property,
    PropertyDetail,
    PropertyMedia,
    RealtorProperty,
)
from rest_framework import serializers

from lib.utils import get_realtor_property_id_for_user
from user_management.models import ClientFamily


User = get_user_model()


class PropertyGetSerializer(serializers.Serializer):
    search = serializers.CharField(required=False)
    sort = serializers.CharField(required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    limit = serializers.IntegerField(min_value=1, required=False)
    user_id = serializers.IntegerField(min_value=1, required=False)

    def validate_sort(self, value):
        if not value:
            return None

        valid_fields = ['date', 'price', 'activity', 'rating']
        valid_orders = ['ASC', 'DESC']

        try:
            field, order = value.split('_')
            if field not in valid_fields:
                raise serializers.ValidationError(
                    f'Invalid sort field. Available fields are: \
                    {", ".join(valid_fields)}'
                )
            if order not in valid_orders:
                raise serializers.ValidationError(
                    f'Invalid sort order. Available orders are: \
                      {", ".join(valid_orders)}'
                )
            return value
        except ValueError:
            raise serializers.ValidationError(
                'Sort parameter must be in format: field_order (e.g., price_ASC)'
            )


class PropertyDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyDetail
        fields = [
            'open_house',
            'property_id',
        ]


class PropertyOffersMixin:
    def get_offers(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')

        if realtor_property_id is None:
            realtor_property_id = getattr(obj, 'realtor_property_id', None)

        if not realtor_property_id:
            return []

        offers = Offer.objects.filter(realtor_property_id=realtor_property_id)
        return PropertyOfferSerializer(offers, many=True).data


class PropertySerializer(PropertyOffersMixin, serializers.ModelSerializer):
    property_details = PropertyDetailSerializer(many=True, read_only=True)
    realtor_property_id = serializers.SerializerMethodField()
    has_disclosures = serializers.SerializerMethodField()
    offers = serializers.SerializerMethodField()
    has_unread_messages = serializers.SerializerMethodField()
    property_rating = serializers.SerializerMethodField()
    is_property_toured = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = '__all__'

    def get_is_property_toured(self, obj):
        # Try to get realtor_property_id from context or object first
        realtor_property_id = getattr(obj, 'realtor_property_id', None)

        if not realtor_property_id:
            request = self.context.get('request')
            if request and request.user:
                user = request.user
                client_id = request.GET.get('user_id')

                if user.user_type == 'realtor':
                    if client_id:
                        realtor_property = obj.realtor_properties.filter(
                            realtor=user, client_id=client_id
                        ).first()
                        realtor_property_id = (
                            realtor_property.id if realtor_property else None
                        )
                else:
                    client = user
                    client_family = ClientFamily.objects.filter(member=user).first()
                    if client_family:
                        client = client_family.parent

                    realtor_property = obj.realtor_properties.filter(
                        client=client
                    ).first()
                    realtor_property_id = (
                        realtor_property.id if realtor_property else None
                    )

        if not realtor_property_id:
            return False

        try:
            realtor_property = RealtorProperty.objects.get(id=realtor_property_id)
            return realtor_property.is_property_toured
        except RealtorProperty.DoesNotExist:
            return False

    def get_realtor_property_id(self, obj):
        if hasattr(obj, 'realtor_property_id'):
            return obj.realtor_property_id
        request = self.context.get('request')
        if not request or not request.user:
            return None

        if request.user.user_type == 'realtor':
            client_id = request.GET.get('user_id')
            if not client_id:
                return None
            realtor_property = obj.realtor_properties.filter(
                realtor=request.user, client_id=client_id
            ).first()
        else:
            client = request.user
            client_family = ClientFamily.objects.filter(member=request.user).first()
            if client_family:
                client = client_family.parent

            realtor_property = obj.realtor_properties.filter(client=client).first()

        return realtor_property.id if realtor_property else None

    def get_offers(self, obj):
        request = self.context.get('request')
        if not request:
            return []

        # Try to get realtor_property_id from context or object first
        realtor_property_id = getattr(obj, 'realtor_property_id', None)

        if not realtor_property_id and request.user:
            user = request.user
            client_id = request.GET.get('user_id')

            if user.user_type == 'realtor':
                # For realtors, we need client_id from request
                if client_id:
                    realtor_property = obj.realtor_properties.filter(
                        realtor=user, client_id=client_id
                    ).first()
                    realtor_property_id = (
                        realtor_property.id if realtor_property else None
                    )
            else:
                # For clients, find their associated realtor property
                client = user
                client_family = ClientFamily.objects.filter(member=user).first()
                if client_family:
                    client = client_family.parent

                realtor_property = obj.realtor_properties.filter(client=client).first()
                realtor_property_id = realtor_property.id if realtor_property else None

        if not realtor_property_id:
            return []

        offers = Offer.objects.filter(realtor_property_id=realtor_property_id)
        return OfferSerializer(offers, many=True).data

    def get_has_disclosures(self, obj):
        realtor_property_id = get_realtor_property_id_for_user(
            obj, self.context.get('request')
        )

        if not realtor_property_id:
            return False

        try:
            # Optimized query with select_related to avoid N+1 queries
            realtor_property = RealtorProperty.objects.select_related('property').get(
                id=realtor_property_id
            )
            return realtor_property.property_disclosures.exists()
        except RealtorProperty.DoesNotExist:
            return False

    def get_has_unread_messages(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')
        print(f'Debug - realtor_property_id from context: {realtor_property_id}')

        if not realtor_property_id:
            realtor_property_id = getattr(obj, 'realtor_property_id', None)

            if not realtor_property_id:
                request = self.context.get('request')

                if request and request.user:
                    user_type = request.user.user_type

                    if user_type == 'realtor':
                        client_id = request.GET.get('user_id')
                        if client_id:
                            realtor_property = obj.realtor_properties.filter(
                                realtor=request.user, client_id=client_id
                            ).first()
                            realtor_property_id = (
                                realtor_property.id if realtor_property else None
                            )
                    else:
                        client = request.user
                        client_family = ClientFamily.objects.filter(
                            member=request.user
                        ).first()
                        if client_family:
                            client = client_family.parent

                        realtor_property = obj.realtor_properties.filter(
                            client=client
                        ).first()
                        realtor_property_id = (
                            realtor_property.id if realtor_property else None
                        )

        if not realtor_property_id:
            return False

        request = self.context.get('request')
        if not request or not request.user:
            return False

        user_type = request.user.user_type
        if user_type == 'realtor':
            return Chat.objects.filter(
                property_id=realtor_property_id, is_chat_viewed_by_client=True
            ).exists()
        elif user_type == 'user':
            return Chat.objects.filter(
                property_id=realtor_property_id, is_chat_viewed_by_client=False
            ).exists()

        return False

    def get_property_rating(self, obj):
        realtor_property_id = getattr(obj, 'realtor_property_id', None)

        if not realtor_property_id:
            request = self.context.get('request')
            if request and request.user:
                if request.user.user_type == 'realtor':
                    client_id = request.GET.get('user_id')
                    if client_id:
                        realtor_property = obj.realtor_properties.filter(
                            realtor=request.user, client_id=client_id
                        ).first()
                        realtor_property_id = (
                            realtor_property.id if realtor_property else None
                        )
                else:
                    realtor_property = obj.realtor_properties.filter(
                        client=request.user
                    ).first()
                    realtor_property_id = (
                        realtor_property.id if realtor_property else None
                    )

        if not realtor_property_id:
            return 0.0

        try:
            realtor_property = RealtorProperty.objects.get(id=realtor_property_id)
            return (
                float(realtor_property.property_rating)
                if realtor_property.property_rating is not None
                else 0.0
            )
        except RealtorProperty.DoesNotExist:
            return 0.0


class OfferSerializer(serializers.ModelSerializer):
    class Meta:
        model = Offer
        fields = '__all__'


class DisclosureFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DisclosureFile
        fields = ['file']


class DisclosureSerializer(serializers.ModelSerializer):
    files = DisclosureFileSerializer(many=True, read_only=True)

    class Meta:
        model = Disclosure
        fields = ['name', 'description', 'url', 'created_date', 'files']
        read_only_fields = ['created_date']

    def create(self, validated_data):
        files_data = self.context['request'].FILES.getlist('files')  # ← Use getlist
        disclosure = Disclosure.objects.create(
            name=validated_data.get('name'),
            description=validated_data.get('description'),
            url=validated_data.get('url'),
            property_id=validated_data.get('property_id'),
        )
        for file in files_data:
            DisclosureFile.objects.create(disclosure=disclosure, file=file)
        return disclosure


class PropertyMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyMedia
        fields = ['photos_list']


class PropertyOfferSerializer(serializers.ModelSerializer):
    date = serializers.DateTimeField(source='created_date')
    offer = serializers.CharField(source='description')

    class Meta:
        model = Offer
        fields = ['id', 'date', 'amount', 'offer']


class PropertyComparableSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()
    listingPrice = serializers.IntegerField(source='property.price')
    closingPrice = serializers.IntegerField(source='closing_price')
    bedsCount = serializers.IntegerField(source='property.no_of_beds')
    bathsCount = serializers.IntegerField(source='property.no_of_baths')
    squareFeet = serializers.IntegerField(source='property.square_feet_size')
    onMarket = serializers.DateTimeField(source='property.open_house_time')
    amountPerSqrFeet = serializers.FloatField(source='amount_per_sqr_feet')
    address = serializers.CharField(source='property.address')
    comparable_id = serializers.SerializerMethodField()
    additional_info = serializers.SerializerMethodField()

    class Meta:
        model = RealtorProperty
        fields = [
            'comparable_id',
            'image',
            'address',
            'listingPrice',
            'closingPrice',
            'bedsCount',
            'bathsCount',
            'squareFeet',
            'onMarket',
            'amountPerSqrFeet',
            'additional_info',
        ]

    def get_image(self, obj):
        return getattr(obj, 'offer_image', None)

    def get_comparable_id(self, obj):
        comparable = self.context.get('comparable')
        return comparable.id if comparable else None

    def get_additional_info(self, obj):
        comparable = self.context.get('comparable')
        return comparable.additional_info if comparable else None


class ComparableSerializer(serializers.Serializer):
    address = serializers.JSONField(required=False)
    realtor_property_id = serializers.IntegerField(required=True)
    client_id = serializers.IntegerField(required=True)
    url = serializers.CharField(max_length=1000, required=False)
    additional_info = serializers.JSONField(required=False)
    is_link_only = serializers.BooleanField(default=False)

    class Meta:
        fields = [
            'address',
            'realtor_property_id',
            'client_id',
            'url',
            'additional_info',
            'is_link_only',
        ]

    def validate(self, data):
        is_link_only = data.get('is_link_only', False)
        url = data.get('url')
        address = data.get('address')

        if is_link_only:
            if not url:
                raise serializers.ValidationError(
                    {'url': 'URL is required for link-only comparables.'}
                )
            if address:
                raise serializers.ValidationError(
                    {
                        'address': 'Address should not be \
                          provided for link-only comparables.'
                    }
                )
        else:
            if not address:
                raise serializers.ValidationError(
                    {'address': 'Address is required for address-based comparables.'}
                )

        return data

    def create(self, validated_data):
        if validated_data.get('is_link_only'):
            return None

        address_data = validated_data.get('address', {})

        property_data = {
            'name': address_data.get('name', ''),
            'address': address_data.get('address', ''),
            'listing_id': address_data.get('listing_id', None),
            'city': address_data.get('city', ''),
            'county_or_parish': address_data.get('county_or_parish', ''),
            'state_or_province': address_data.get('state_or_province', ''),
            'zip_code': address_data.get('zip_code', ''),
            'image': address_data.get('image', ''),
            'additional_information': address_data.get('additional_information', ''),
            'is_deadline_checked': address_data.get('is_deadline_checked', False),
            'latitude': address_data.get('latitude', None),
            'longitude': address_data.get('longitude', None),
            'no_of_baths': address_data.get('no_of_baths', 0),
            'no_of_beds': address_data.get('no_of_beds', 0),
            'note': address_data.get('note', ''),
            'price': address_data.get('price', 0),
            'square_feet_size': address_data.get('square_feet_size', 0),
        }

        property = Property.objects.create(**property_data)

        photos_list = address_data.get('photosList')
        if photos_list and isinstance(photos_list, list):
            PropertyMedia.objects.create(property_id=property, photos_list=photos_list)

        return property


class ComparableDetailSerializer(serializers.ModelSerializer):
    to_property = PropertyComparableSerializer()
    additional_info = serializers.JSONField(required=False)
    is_link_only = serializers.BooleanField()
    url = serializers.CharField(max_length=255, required=False)

    class Meta:
        model = Comparable
        fields = ['to_property', 'url', 'additional_info', 'is_link_only']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.is_link_only:
            data['to_property'] = None
        return data


class PropertyDetailsSerializer(PropertyOffersMixin, serializers.ModelSerializer):
    OpenHouseTime = serializers.DateTimeField(source='open_house_time')
    bedsCount = serializers.IntegerField(source='no_of_beds')
    bathsCount = serializers.IntegerField(source='no_of_baths')
    squareFeet = serializers.IntegerField(source='square_feet_size')
    zillowIntegration = serializers.BooleanField(source='zillow_integration')
    photos_list = serializers.SerializerMethodField()
    offers = serializers.SerializerMethodField()
    additionalInformation = serializers.CharField(source='additional_information')
    disclosure = serializers.SerializerMethodField()
    comparables = serializers.SerializerMethodField()
    first_offer = serializers.IntegerField()
    second_offer = serializers.IntegerField()
    last_offer = serializers.IntegerField()
    has_unread_messages = serializers.SerializerMethodField()
    is_property_toured = serializers.SerializerMethodField()
    property_rating = serializers.FloatField()

    class Meta:
        model = Property
        fields = '__all__'

    def get_is_property_toured(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')
        if not realtor_property_id:
            return False

        try:
            realtor_property = RealtorProperty.objects.get(id=realtor_property_id)
            return realtor_property.is_property_toured
        except RealtorProperty.DoesNotExist:
            return False

    def get_photos_list(self, obj):
        media_entries = obj.property_media.all()  # Uses related_name from PropertyMedia
        flattened_photos = []
        for media in media_entries:
            if media.photos_list:
                flattened_photos.extend(media.photos_list)
        return flattened_photos

    def get_comparables(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')
        comparables = []
        if not realtor_property_id:
            return comparables

        comparable_queryset = (
            Comparable.objects.filter(from_property_id=realtor_property_id)
            .prefetch_related('to_property', 'to_property__property')
            .select_related('to_property__property')
        )

        for comparable in comparable_queryset:
            if comparable.is_link_only:
                comparable_data = {
                    'comparable_id': comparable.id,
                    'is_link_only': True,
                    'url': comparable.url,
                    'additional_info': comparable.additional_info,
                }
                comparables.append(comparable_data)
                continue
            to_property = comparable.to_property
            latest_offer = Offer.objects.filter(
                realtor_property_id=to_property.id
            ).values('amount')[:1]
            to_property.closing_price = (
                latest_offer[0]['amount'] if latest_offer else None
            )

            media = PropertyMedia.objects.filter(
                property_id=to_property.property_id
            ).values('photos_list')[:1]
            to_property.offer_image = media[0]['photos_list'] if media else None

            if to_property.property.price and to_property.property.square_feet_size:
                to_property.amount_per_sqr_feet = (
                    to_property.property.price / to_property.property.square_feet_size
                )
            else:
                to_property.amount_per_sqr_feet = None

            comparable_data = PropertyComparableSerializer(
                to_property, context={'comparable': comparable}
            ).data
            comparable_data['is_link_only'] = False
            comparables.append(comparable_data)
        return comparables

    def get_disclosure(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')
        if not realtor_property_id:
            return []

        realtor_property = RealtorProperty.objects.filter(
            id=realtor_property_id,
        ).first()

        if not realtor_property:
            return []

        return DisclosureSerializer(
            realtor_property.property_disclosures.all(), many=True
        ).data

    def get_has_unread_messages(self, obj):
        realtor_property_id = self.context.get('realtor_property_id')
        if not realtor_property_id:
            return False

        request = self.context.get('request')
        if not request or not request.user:
            return False

        user_type = request.user.user_type
        if user_type == 'realtor':
            return Chat.objects.filter(
                property_id=realtor_property_id, is_chat_viewed_by_client=True
            ).exists()
        elif user_type == 'user':
            return Chat.objects.filter(
                property_id=realtor_property_id, is_chat_viewed_by_client=False
            ).exists()
        return False

    def to_representation(self, instance):
        representation = super().to_representation(instance)

        representation['offerGraph'] = {
            'askedPrice': representation['price'],
            'firstOffer': representation.pop('first_offer'),
            'secondOffer': representation.pop('second_offer'),
            'closingOffer': representation.pop('last_offer'),
        }
        return representation


class SendMessageSerializer(serializers.Serializer):
    realtor_property_id = serializers.IntegerField(required=True)
    message = serializers.CharField(required=True)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'phone']


class MessageSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Chat
        fields = ['id', 'user', 'message', 'is_chat_viewed_by_client', 'timestamp']


class ReceiveMessageSerializer(serializers.Serializer):
    messages = MessageSerializer(many=True)
    page = serializers.IntegerField()
    has_next = serializers.BooleanField()
    total = serializers.IntegerField()


class PollNewMessageSerializer(serializers.Serializer):
    messages = MessageSerializer(many=True)


class PropertyPostSerializer(serializers.ModelSerializer):
    address = serializers.CharField(max_length=1000, required=True)
    note = serializers.CharField(
        max_length=3000, required=False, allow_blank=True, allow_null=True
    )  # noqa: E501

    class Meta:
        model = Property
        fields = '__all__'


class OfferCreateSerializer(serializers.ModelSerializer):
    realtor_property_id = serializers.IntegerField(required=True)
    offer_date = serializers.DateField(required=True)
    contingencies_info = serializers.JSONField(required=False, allow_null=True)
    description = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Offer
        fields = [
            'amount',
            'description',
            'realtor_property_id',
            'contingencies_info',
            'offer_date',
        ]

    def validate_realtor_property_id(self, value):
        request_user = self.context['request'].user
        try:
            RealtorProperty.objects.get(id=value, realtor=request_user)
        except RealtorProperty.DoesNotExist:
            raise serializers.ValidationError(
                'Invalid or unauthorized Realtor Property.',
            )
        return value

    def create(self, validated_data):
        realtor_property_id = validated_data.pop('realtor_property_id')
        realtor_property = RealtorProperty.objects.get(id=realtor_property_id)
        return Offer.objects.create(realtor_property=realtor_property, **validated_data)


class RatingSerializer(serializers.ModelSerializer):
    class Meta:
        model = RealtorProperty
        fields = ['property_rating']
        extra_kwargs = {
            'property_rating': {'required': True, 'min_value': 0, 'max_value': 5}
        }

    def validate(self, data):
        # Ensure the instance has all required FKs
        if not all(
            [
                self.instance.property_id,
                self.instance.client_id,
                self.instance.realtor_id,
            ]
        ):
            raise serializers.ValidationError('Missing required foreign keys')
        return data


class TourStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = RealtorProperty
        fields = ['is_property_toured']
