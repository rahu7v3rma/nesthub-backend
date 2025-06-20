"""shared app library"""

from django.conf import settings
from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect
from django.shortcuts import resolve_url
from rest_framework import status
from rest_framework.response import Response

from lib.constants import (
    CODE_ACCESS_FORBIDDEN,
    CODE_BAD_CREDENTIALS,
    CODE_EMAIL_ALREADY_EXISTS,
    CODE_INVALID_REQUEST,
    CODE_MEMBER_ID_VERIFICATION_FAILED,
    CODE_NOT_FOUND,
    CODE_PASSWORD_DOES_NOT_CONFORM,
    CODE_SERVER_ERROR,
    CODE_VERIFICATION_FAILED,
)


# pylint: disable=too-many-return-statements
def get_response(code, message, data):
    if code == CODE_INVALID_REQUEST:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_400_BAD_REQUEST,
                'data': data,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif code == CODE_NOT_FOUND:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_404_NOT_FOUND,
                'data': data,
            },
            status=status.HTTP_404_NOT_FOUND,
        )
    elif code == CODE_BAD_CREDENTIALS:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_400_BAD_REQUEST,
                'data': data,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif code == CODE_ACCESS_FORBIDDEN:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_403_FORBIDDEN,
                'data': data,
            },
            status=status.HTTP_403_FORBIDDEN,
        )
    elif code == CODE_SERVER_ERROR:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'data': data,
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    elif code == CODE_PASSWORD_DOES_NOT_CONFORM:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_400_BAD_REQUEST,
                'data': data,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif code in (
        CODE_VERIFICATION_FAILED,
        CODE_MEMBER_ID_VERIFICATION_FAILED,
    ):
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_400_BAD_REQUEST,
                'data': data,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    elif code == CODE_EMAIL_ALREADY_EXISTS:
        return Response(
            {
                'success': False,
                'message': message,
                'code': code,
                'status': status.HTTP_401_UNAUTHORIZED,
                'data': data,
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )
    else:
        return Response(
            {
                'success': True,
                'message': message,
                'status': code,
                'data': data,
            },
            status=status.HTTP_200_OK,
        )


def redirect(to_url, *args, permanent=False, **kwargs):
    """
    A re-implementation of `django.shortcuts.redirect` which seeds the
    allowed schemas with extra values from a configuration setting
    """
    redirect_class = (
        HttpResponsePermanentRedirect if permanent else HttpResponseRedirect
    )

    redirect_class.allowed_schemes += settings.REDIRECT_EXTRA_ALLOWED_SCHEMAS

    return redirect_class(resolve_url(to_url, *args, **kwargs))
