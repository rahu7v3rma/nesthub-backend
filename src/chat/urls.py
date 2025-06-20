# /home/webexpert/aviel/nesthub-backend/src/chat/urls.py
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ChatViewSet


router = DefaultRouter()
router.register(r'', ChatViewSet, basename='chat')

urlpatterns = [
    path('', include(router.urls)),
]
