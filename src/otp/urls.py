from django.urls import path

from .views import SendOtpAPIView, VerifyOtpAPIView


urlpatterns = [
    path('send', SendOtpAPIView.as_view(), name='send_otp'),
    path('verify', VerifyOtpAPIView.as_view(), name='verify_otp'),
]
