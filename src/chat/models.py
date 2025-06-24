# /home/webexpert/aviel/nesthub-backend/src/chat/models.py
from django.db import models
from properties.models import RealtorProperty

from user_management.models import CustomUser


class Chat(models.Model):
    # Use string reference to avoid import issues
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='chats')
    property = models.ForeignKey(
        RealtorProperty, on_delete=models.CASCADE, related_name='chats'
    )
    message = models.TextField()
    is_chat_viewed_by_client = models.BooleanField(blank=True, null=True, default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'Message from {self.user} about property {self.property_id}'
