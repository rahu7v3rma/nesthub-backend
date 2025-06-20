from django.urls import path

from .views import OAuthAuthorizeView, OAuthRedirectView


urlpatterns = [
    path('oauth/authorize', OAuthAuthorizeView.as_view(), name='oauth-authorize'),
    path('oauth/redirect', OAuthRedirectView.as_view(), name='oauth-redirect'),
]
