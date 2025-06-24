from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from properties import views


urlpatterns = [
    path('', views.PropertyView.as_view(), name='property'),
    path('<int:pk>/', views.PropertyView.as_view(), name='property-detail'),
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
        views.OfferView.as_view(),
        name='create_new_offer',
    ),
    path(
        '<int:property_id>/offer/<int:offer_id>',
        views.OfferView.as_view(),
        name='offer-delete',
    ),
    path(
        '<int:pk>/add-disclosure',
        views.DisclosureView.as_view(),
        name='add-disclosure',
    ),
    path(
        '<int:pk>/add-comparable',
        views.ComparableView.as_view(),
        name='add-comparable',
    ),
    path(
        '<int:pk>/comparable/<int:comparable_id>',
        views.ComparableView.as_view(),
        name='update-delete-comparable',
    ),
    path(
        '<int:pk>/rate',
        views.UpdateRatingAPI.as_view(),
        name='update-rating',
    ),
    path(
        '<int:pk>/update-tour-status',
        views.UpdateTourStatusAPI.as_view(),
        name='update-tour-status',
    ),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
