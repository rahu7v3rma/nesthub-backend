from otp.utils import send_otp, verify_otp
from rest_framework.response import Response
from rest_framework.views import APIView


class SendOtpAPIView(APIView):
    def post(self, request):
        user = request.user
        if send_otp(user):
            return Response({'message': 'OTP sent to your email'})
        else:
            return Response(
                {'error': 'Failed to send OTP. Please try again.'}, status=500
            )


class VerifyOtpAPIView(APIView):
    def post(self, request):
        otp = request.data.get('otp')
        user = request.user
        if otp is None:
            return Response({'error': 'OTP not provided'}, status=400)

        if verify_otp(user, otp):
            return Response({'message': 'OTP verified'})
        else:
            return Response({'error': 'Invalid or expired OTP'}, status=400)
