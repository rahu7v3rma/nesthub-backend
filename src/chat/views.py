# /home/webexpert/aviel/nesthub-backend/src/chat/views.py
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Chat
from .serializers import ChatSerializer


class IsUserOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user


class ChatViewSet(viewsets.ModelViewSet):
    serializer_class = ChatSerializer
    permission_classes = [permissions.IsAuthenticated, IsUserOrReadOnly]

    def get_queryset(self):
        return Chat.objects.all()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'])
    def property_messages(self, request):
        """Get the latest 20 messages for a specific property."""
        property_id = request.query_params.get('property_id')

        if not property_id:
            return Response(
                {'error': 'property_id query parameter is required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Directly filter by property_id instead of fetching the object first
            messages = Chat.objects.filter(property_id=property_id).order_by(
                '-timestamp'
            )[:20]
            serializer = self.get_serializer(messages, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
