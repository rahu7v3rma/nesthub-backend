from django.urls import path
from properties import views


urlpatterns = [
    path('', views.PropertyView.as_view(), name='property'),
    path(
        'details/<int:property_id>',
        views.PropertyDetailsView.as_view(),
        name='property_details',
    ),
    path('chat', views.SendMessageView.as_view(), name='send_message'),
    path(
        '<int:property_id>/chat',
        views.ReceiveMessageView.as_view(),
        name='receive_message',
    ),
    path(
        '<int:property_id>/chat/new-messages',
        views.PollNewMessagesView.as_view(),
        name='receive_new_message',
    ),
    path(
        'offer',
        views.CreateNewOfferView.as_view(),
        name='create_new_offer',
    ),
]
