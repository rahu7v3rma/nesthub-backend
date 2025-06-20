# /home/webexpert/aviel/nesthub-backend/src/chat/serializers.py
from django.contrib.auth import get_user_model
from rest_framework import serializers

from user_management.models import CustomUser

from .models import Chat


User = get_user_model()


class UserBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'name']


class ChatSerializer(serializers.ModelSerializer):
    user_details = UserBasicSerializer(source='user', read_only=True)

    class Meta:
        model = Chat
        fields = ['id', 'user', 'property', 'message', 'timestamp', 'user_details']
        read_only_fields = ['user', 'timestamp']
