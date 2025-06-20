import re

from rest_framework import serializers

from user_management.models import ClientFamily, CustomUser
from user_management.validator import SignupRequest


class UserSerializer(serializers.ModelSerializer):
    user_type = serializers.CharField(read_only=True)

    class Meta:
        model = CustomUser
        fields = [
            'id',
            'name',
            'email',
            'phone',
            'company',
            'license_id',
            'user_type',
            'address',
            'timestamp',
        ]


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, trim_whitespace=False)


class SignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'name',
            'email',
            'phone',
            'password',
            'company',
            'license_id',
            'address',
            'user_type',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'user_type': {'default': 'realtor'},
        }

    def validate_password(self, value):
        """Validate password according to requirements"""
        # Password strength validation
        if len(value) < 8:
            raise serializers.ValidationError(
                'Password must be at least 8 characters long.'
            )

        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError(
                'Password must contain at least one digit.'
            )

        if not any(char.isupper() for char in value):
            raise serializers.ValidationError(
                'Password must contain at least one uppercase letter.'
            )

        if not any(char.islower() for char in value):
            raise serializers.ValidationError(
                'Password must contain at least one lowercase letter.'
            )

        if not any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for char in value):
            raise serializers.ValidationError(
                'Password must contain at least one special character.'
            )

        return value

    def validate_license_id(self, value):
        """Validate license_id for uniqueness"""
        if CustomUser.objects.filter(license_id=value).exists():
            raise serializers.ValidationError('License ID already exists.')
        return value

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            name=validated_data['name'],
            phone=validated_data['phone'],
            company=validated_data.get('company', ''),
            license_id=validated_data.get('license_id', ''),
            address=validated_data.get('address', ''),
            user_type=validated_data.get('user_type', 'realtor'),
        )
        return user


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordVerifySerializer(serializers.Serializer):
    token = serializers.CharField()


class ResetPasswordConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField()

    def validate_password(self, value):
        try:
            SignupRequest.validate_password(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))
        return value


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate_new_password(self, new_password):
        """
        Check that the old password and the new password are not the same.
        """
        if new_password == self.initial_data.get('old_password'):
            raise serializers.ValidationError(
                'New password cannot be the same as the old password'
            )
        return new_password


class VerifyAccountSerializer(serializers.Serializer):
    # pylint: disable=abstract-method
    token = serializers.CharField()


class UnverifiedTokenSerializer(serializers.Serializer):
    unverified_auth_token = serializers.CharField()


class ClientPostRequestSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    phone = serializers.CharField(required=True)

    def validate_email(self, email):
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError('Email address already exists')
        return email

    def validate_phone(self, phone):
        if CustomUser.objects.filter(phone=phone).exists():
            raise serializers.ValidationError('Phone number already exists')
        if not re.match(r'^\d{10}$', phone):
            raise serializers.ValidationError('Phone number must be 10 digits')
        return phone

    def validate(self, data):
        errors = {}

        if 'email' not in data:
            errors['email'] = ['This field is required.']
        elif CustomUser.objects.filter(email=data.get('email')).exists():
            errors['email'] = ['Email address already exists']
        elif 'email' in data and not re.match(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data.get('email')
        ):
            errors['email'] = ['Enter a valid email address.']

        if 'phone' not in data:
            errors['phone'] = ['This field is required.']
        elif CustomUser.objects.filter(phone=data.get('phone')).exists():
            errors['phone'] = ['Phone number already exists']
        elif 'phone' in data and not re.match(r'^\d{10}$', data.get('phone')):
            errors['phone'] = ['Phone number must be 10 digits']

        if 'name' not in data:
            errors['name'] = ['This field is required.']

        if errors:
            raise serializers.ValidationError(errors)

        return data


class ClientPutRequestSerializer(serializers.Serializer):
    name = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)

    def validate_email(self, email):
        request_client = self.context.get('request_client')
        if (
            email
            and request_client
            and email != request_client.email
            and CustomUser.objects.filter(email=email).exists()
        ):
            raise serializers.ValidationError('Email address already exists')
        return email

    def validate_phone(self, phone):
        request_client = self.context.get('request_client')
        if phone and request_client and CustomUser.objects.filter(phone=phone).exists():
            raise serializers.ValidationError('Phone number already exists')
        if phone and not re.match(r'^\d{10}$', phone):
            raise serializers.ValidationError('Phone number must be 10 digits')
        return phone


class MemberSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(source='member.id')
    name = serializers.CharField(source='member.name')
    email = serializers.EmailField(source='member.email')
    phone = serializers.CharField(source='member.phone')

    class Meta:
        model = ClientFamily
        fields = ['id', 'name', 'email', 'phone']


class ClientSerializer(serializers.ModelSerializer):
    property_count = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'email', 'phone', 'property_count']

    def get_property_count(self, obj):
        return obj.client_properties.count()


class ClientDetailSerializer(serializers.ModelSerializer):
    members = MemberSerializer(source='client_families', many=True, read_only=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'email', 'phone', 'members']


class ClientGetSerializer(serializers.Serializer):
    """
    Serializer to validate query params for the get method of ClientView
    """

    search = serializers.CharField(required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    limit = serializers.IntegerField(min_value=1, required=False)
    active = serializers.BooleanField(required=False, allow_null=True)
