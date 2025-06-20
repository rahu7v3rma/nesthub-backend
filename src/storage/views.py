import logging

from django.conf import settings
from django.shortcuts import redirect
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from .google_drive import GoogleDriveStorage
from .models import GoogleOAuthAuthorizationRequest


logger = logging.getLogger(__name__)


class OAuthAuthorizeView(APIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [SessionAuthentication]

    def get(self, request):
        if not settings.GOOGLE_DRIVE_STORAGE_ENABLED:
            return Response(
                {
                    'success': False,
                    'message': 'Not found.',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        authorization_url, authorization_state = (
            GoogleDriveStorage().get_authorization_url()
        )

        GoogleOAuthAuthorizationRequest.objects.create(state=authorization_state)

        return redirect(authorization_url, permanent=False)


class OAuthRedirectView(APIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [SessionAuthentication]

    def get(self, request):
        if not settings.GOOGLE_DRIVE_STORAGE_ENABLED:
            return Response(
                {
                    'success': False,
                    'message': 'Not found.',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        code = request.query_params.get('code')
        state = request.query_params.get('state')

        latest_request = GoogleOAuthAuthorizationRequest.objects.order_by(
            '-created_date'
        ).first()

        if not latest_request or latest_request.used or latest_request.state != state:
            logger.error(f'oauth redirect failed with wrong state: {state}')
            return Response(
                {
                    'success': False,
                    'message': 'Bad request state.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            GoogleDriveStorage().exchange_code(code)

            latest_request.used = True
            latest_request.save(update_fields=['used'])

            return Response(
                {
                    'success': True,
                    'message': 'Authorization complete.',
                    'status': status.HTTP_200_OK,
                    'data': {},
                },
                status=status.HTTP_200_OK,
            )
