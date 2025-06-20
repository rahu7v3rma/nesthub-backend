from functools import wraps

from rest_framework import status
from rest_framework.response import Response

from user_management.models import CustomUser, RealtorClient


def verify_path_client(api_view):
    @wraps(api_view)
    def wrapped_api_view(request, *args, **kwargs):
        request_realtor = request.user
        request_client = CustomUser.objects.filter(id=kwargs.get('client_id')).first()
        if not request_client:
            return Response(
                {
                    'success': False,
                    'message': 'Client not found.',
                    'code': 'not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
            )
        if (
            not getattr(request_client, 'user_type', None)
            or request_client.user_type != 'user'
        ):
            return Response(
                {
                    'success': False,
                    'message': 'Client not found.',
                    'code': 'not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if not RealtorClient.objects.filter(
            realtor=request_realtor, client=request_client
        ).exists():
            return Response(
                {
                    'success': False,
                    'message': 'Client not found.',
                    'code': 'not_found',
                    'status': status.HTTP_404_NOT_FOUND,
                    'data': {},
                },
            )

        setattr(request, 'client', request_client)

        return api_view(request, *args, **kwargs)

    return wrapped_api_view
