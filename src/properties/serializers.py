# Third-party imports
# Local application imports
from chat.models import Chat
from django.contrib.auth import get_user_model
from properties.models import (
    Disclosure,
    Offer,
    Property,
    PropertyDetail,
    PropertyMedia,
    RealtorProperty,
)
from rest_framework import serializers


User = get_user_model()


class PropertyGetSerializer(serializers.Serializer):
    search = serializers.CharField(required=False)
    sort = serializers.ChoiceField(
        choices=('ASC', 'DESC'),
        required=False,
        error_messages={
            'invalid_choice': 'Provided choice is invalid, Available choices are: "ASC" and "DESC".'  # noqa: E501
        },
    )
    page = serializers.IntegerField(min_value=1, required=False)
    limit = serializers.IntegerField(min_value=1, required=False)
    user_id = serializers.IntegerField(min_value=1, required=False)


class PropertyDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyDetail
        fields = [
            'open_house',
            'property_id',
        ]


class PropertySerializer(serializers.ModelSerializer):
    property_details = PropertyDetailSerializer(many=True, read_only=True)
    realtor_property_id = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = '__all__'

    def get_realtor_property_id(self, obj):
        return getattr(obj, 'realtor_property_id', None)


class OfferSerializer(serializers.ModelSerializer):
    class Meta:
        model = Offer
        fields = '__all__'


class DisclosureSerializer(serializers.ModelSerializer):
    dateTime = serializers.DateTimeField(source='created_date')

    class Meta:
        model = Disclosure
        fields = ['name', 'dateTime']


class PropertyMediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyMedia
        fields = ['image']


class PropertyOfferSerializer(serializers.ModelSerializer):
    date = serializers.DateTimeField(source='created_date')
    offer = serializers.CharField(source='description')

    class Meta:
        model = Offer
        fields = ['date', 'amount', 'offer']


class PropertyComparableSerializer(serializers.ModelSerializer):
    image = serializers.CharField(source='offer_image')
    listingPrice = serializers.IntegerField(source='price')
    closingPrice = serializers.IntegerField(source='closing_price')
    bedsCount = serializers.IntegerField(source='no_of_beds')
    bathsCount = serializers.IntegerField(source='no_of_baths')
    squareFeet = serializers.IntegerField(source='square_feet_size')
    onMarket = serializers.DateTimeField(source='open_house_time')
    amountPerSqrFeet = serializers.FloatField(source='amount_per_sqr_feet')

    class Meta:
        model = Property
        fields = [
            'image',
            'address',
            'listingPrice',
            'closingPrice',
            'bedsCount',
            'bathsCount',
            'squareFeet',
            'onMarket',
            'amountPerSqrFeet',
        ]


class PropertyDetailsSerializer(serializers.ModelSerializer):
    OpenHouseTime = serializers.DateTimeField(source='open_house_time')
    bedsCount = serializers.IntegerField(source='no_of_beds')
    bathsCount = serializers.IntegerField(source='no_of_baths')
    squareFeet = serializers.IntegerField(source='square_feet_size')
    zillowIntegration = serializers.BooleanField(source='zillow_integration')
    additionalInformation = serializers.CharField(source='additional_information')
    images = PropertyMediaSerializer(source='propertymedia_set', many=True)
    offers = PropertyOfferSerializer(source='property_offers', many=True)
    disclosure = DisclosureSerializer(source='property_disclosures', many=True)
    comparables = PropertyComparableSerializer(
        source='comparables_with_last_offer', many=True
    )
    first_offer = serializers.IntegerField()
    second_offer = serializers.IntegerField()
    last_offer = serializers.IntegerField()

    class Meta:
        model = Property
        fields = [
            'address',
            'city',
            'state_or_province',
            'image',
            'images',
            'price',
            'OpenHouseTime',
            'bedsCount',
            'bathsCount',
            'squareFeet',
            'zillowIntegration',
            'additionalInformation',
            'offers',
            'disclosure',
            'comparables',
            'first_offer',
            'second_offer',
            'last_offer',
        ]

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
        fields = ['id', 'user', 'message', 'timestamp']


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

    class Meta:
        model = Offer
        fields = ['amount', 'description', 'realtor_property_id']

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
