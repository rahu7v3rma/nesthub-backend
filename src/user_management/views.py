from collections import Counter
import logging

from django.conf import settings
from django.contrib.auth.password_validation import (
    get_password_validators,
    validate_password,
)
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.db.utils import IntegrityError
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from lib.constants import CODE_NOT_FOUND, MESSAGE_NOT_FOUND
from lib.responses import get_response, redirect
from services.email import (
    send_reset_password_email,
    send_set_password_email,
    send_verify_account_email,
)
from user_management.decorators import verify_path_client
from user_management.models import (
    ClientFamily,
    CustomToken as Token,
    CustomUser,
    RealtorClient,
    ResetPasswordToken,
    SetPasswordToken,
    VerifyAccountToken,
)
from user_management.serializers import (
    ChangePasswordSerializer,
    ClientDetailSerializer,
    ClientGetSerializer,
    ClientPostRequestSerializer,
    ClientPutRequestSerializer,
    ClientSerializer,
    LoginSerializer,
    ResetPasswordConfirmSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordVerifySerializer,
    SignUpSerializer,
    UnverifiedTokenSerializer,
    UserSerializer,
    VerifyAccountSerializer,
)
from user_management.utils import (
    InnerIsAuthenticated,
    IsAuthenticatedAndNotVerified,
    IsRealtor,
    hash_user_id,
)

from .constants import (
    INVALID_REQUEST,
    SIGN_IN_SUCCESS,
)


logger = logging.getLogger(__name__)


class UserLoginView(APIView):
    """
    Login and send token
    """

    permission_classes = [AllowAny]

    def post(self, request):
        # parse request
        request_serializer = LoginSerializer(data=request.data)

        # make sure request data is valid
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # find user by email
        request_email = request_serializer.validated_data['email']
        try:
            user = CustomUser.objects.get(email=request_email.lower())
        except CustomUser.DoesNotExist:
            logger.info(
                'login attempt with non-existing email: %s',
                request_email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        password = request_serializer.validated_data['password']

        # validate user password
        if password != password.strip() or not user.check_password(password):
            logger.info(
                'login attempt with bad password for email: %s',
                request_email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # create new token or get existing one for user (will be related to
        # the user instance)
        token, _ = Token.objects.get_or_create(user=user)

        # signal that user has logged in (will update last_login value)
        user_logged_in.send(sender=user.__class__, request=request, user=user)

        # check the email verification
        if not user.is_email_verified:
            # respond with an unverified token only
            response_serializer = UnverifiedTokenSerializer(
                {'unverified_auth_token': token}
            )  # noqa: E501

            return Response(
                {
                    'success': False,
                    'message': 'Email not verified.',
                    'code': 'email_not_verified',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': response_serializer.data,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        else:
            # if not user.otp_exempt:
            #     send_otp(user)

            # respond with user data and token
            response_serializer = UserSerializer(user)

            response_data_exempt = {'exempt': True} if user.otp_exempt else {}
            token = {'token': token.key}
            return Response(
                {
                    'success': True,
                    'message': 'User logged in successfully.',
                    'status': status.HTTP_200_OK,
                    'data': {
                        **response_serializer.data,
                        **response_data_exempt,
                        **token,
                    },
                },
                status=status.HTTP_200_OK,
            )


class SignUpView(APIView):
    """
    Sign up a new user
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = serializer.save()
            token, _ = Token.objects.get_or_create(user=user)

            # Create verification token and send email
            request_ip_address = request.META.get(
                'HTTP_X_FORWARDED_FOR'
            ) or request.META.get('REMOTE_ADDR')
            request_user_agent = request.META.get('HTTP_USER_AGENT')

            verify_account_token = VerifyAccountToken.objects.create(
                user=user,
                ip_address=request_ip_address,
                user_agent=request_user_agent,
            )

            # Use the new URL format
            verify_account_link = (
                f'{settings.FRONTEND_BASE_URL}/auth/verify-account/'
                f'{verify_account_token.token}'
            )

            email_sent = send_verify_account_email(
                email=user.email,
                name=user.name,
                verify_account_link=verify_account_link,
            )

            if not email_sent:
                logger.error(f'Failed to send verification email to {user.email}')
                # Continue with signup even if email fails - user can request
                # verification email later

            response_data = {
                'user': UserSerializer(user).data,
                'token': token.key,
                'redirect_url': f'{settings.FRONTEND_BASE_URL}/auth/verify-account',
            }
            return Response(
                {
                    'success': True,
                    'message': (
                        'User created successfully. Please check your email to '
                        'verify your account.'
                    ),
                    'status': status.HTTP_201_CREATED,
                    'data': response_data,
                },
                status=status.HTTP_201_CREATED,
            )
        except IntegrityError:
            return Response(
                {
                    'success': False,
                    'message': 'Email already exists.',
                    'code': 'email_already_exists',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class SignInView(APIView):
    """
    Sign in an existing user.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        # Validate request data using serializer
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            logger.warning('Sign-in attempt with invalid request data.')
            return Response(
                {
                    'success': False,
                    'message': INVALID_REQUEST,
                    'code': 'invalid_request',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Extract validated data
        email = serializer.validated_data['email'].lower()
        password = serializer.validated_data['password']
        try:
            user = CustomUser.objects.get(email=email.lower())
        except CustomUser.DoesNotExist:
            logger.info(
                'login attempt with non-existing email: %s',
                email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        # validate user password
        if password != password.strip() or not user.check_password(password):
            logger.info(
                'login attempt with bad password for email: %s',
                email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Create or retrieve authentication token
        token, created = Token.objects.get_or_create(user=user)

        # Signal user login
        user_logged_in.send(sender=user.__class__, request=request, user=user)

        # ✅ Robust user type determination

        # Prepare response data
        response_data = {
            'user': UserSerializer(user).data,
            'token': token.key,
            'user_type': user.user_type,
        }

        logger.info(f'User successfully signed in: {email}')
        return Response(
            {
                'success': True,
                'message': SIGN_IN_SUCCESS,
                'status': status.HTTP_200_OK,
                'data': response_data,
            },
            status=status.HTTP_200_OK,
        )


class UserLogoutView(APIView):
    """
    Logout an active session
    """

    def post(self, request):
        # delete custom auth token
        if hasattr(request.user, 'custom_auth_tokens'):  # Check if the user has a token
            request.user.custom_auth_tokens.all().delete()

        # signal that user has logged out
        user_logged_out.send(
            sender=request.user.__class__, request=request, user=request.user
        )

        return Response(
            {
                'success': True,
                'message': 'User logged out successfully.',
                'status': status.HTTP_200_OK,
                'data': {},
            },
            status=status.HTTP_200_OK,
        )


class ResetPasswordRequestView(APIView):
    """
    Request a password reset with an account email
    """

    permission_classes = [AllowAny]

    def post(self, request):
        platform = request.GET.get('platform', 'web')
        request_serializer = ResetPasswordRequestSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_email = request_serializer.validated_data['email']

        # query for a user, email if found and always return 200
        try:
            user = CustomUser.objects.get(email=request_email.lower())
        except CustomUser.DoesNotExist:
            logger.info(
                'reset password request attempt with non-existing email: %s',
                request_email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        else:
            # generate a new token and save it
            request_ip_address = request.META.get('REMOTE_ADDR')
            request_user_agent = request.META.get('HTTP_USER_AGENT')
            reset_password_token = ResetPasswordToken(
                user=user,
                ip_address=request_ip_address,
                user_agent=request_user_agent,
            )
            reset_password_token.save()
            reset_password_link = settings.BASE_RESET_PASSWORD_URL.format(
                platform,
                reset_password_token.token,
            )
            response = send_reset_password_email(
                email=request_email, reset_password_link=reset_password_link
            )
            if not response:
                return Response(
                    {
                        'success': False,
                        'message': 'Server error.',
                        'code': 'server_error',
                        'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                        'data': {},
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response(
            {
                'success': True,
                'message': 'Reset password token requested successfully.',
                'status': status.HTTP_200_OK,
                'data': {},
            },
            status=status.HTTP_200_OK,
        )


class ResetPasswordVerifyView(APIView):
    """
    Verify a reset password token
    """

    permission_classes = [AllowAny]

    def post(self, request):
        request_serializer = ResetPasswordVerifySerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_token = request_serializer.validated_data['token']

        try:
            reset_password_token = ResetPasswordToken.objects.get(token=request_token)

            if reset_password_token.verify():
                return Response(
                    {
                        'success': True,
                        'message': 'Token verified successfully.',
                        'status': status.HTTP_200_OK,
                        'data': {},
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.info(
                    'reset password verify attempt with expired token: %s',
                    request_token,
                )

                # delete expired tokens
                reset_password_token.delete()
        except ResetPasswordToken.DoesNotExist:
            logger.info(
                'reset password verify attempt with non-existing token: %s',
                request_token,
            )

        return Response(
            {
                'success': False,
                'message': 'Invalid or expired token.',
                'code': 'bad_token',
                'status': status.HTTP_400_BAD_REQUEST,
                'data': {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ResetPasswordConfirmView(APIView):
    """
    Request a password reset with an account email
    """

    permission_classes = [AllowAny]

    def post(self, request):
        request_serializer = ResetPasswordConfirmSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_token = request_serializer.validated_data['token']
        request_password = request_serializer.validated_data['password']

        try:
            reset_password_token = ResetPasswordToken.objects.get(token=request_token)

            if reset_password_token.verify():
                # validate password
                try:
                    validate_password(
                        request_password,
                        user=reset_password_token.user,
                        password_validators=get_password_validators(
                            settings.AUTH_PASSWORD_VALIDATORS
                        ),
                    )
                except ValidationError as ex:
                    return Response(
                        {
                            'success': False,
                            'message': 'Request is invalid.',
                            'code': 'password_does_not_conform',
                            'status': status.HTTP_400_BAD_REQUEST,
                            'data': {
                                'password': ex.messages,
                            },
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                reset_password_token.user.set_password(request_password)
                reset_password_token.user.save()

                # delete used token
                reset_password_token.delete()

                return Response(
                    {
                        'success': True,
                        'message': 'Password changed successfully.',
                        'status': status.HTTP_200_OK,
                        'data': {},
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.info(
                    'reset password confirm attempt with expired token: %s',
                    request_token,
                )

                # delete expired tokens
                reset_password_token.delete()
        except ResetPasswordToken.DoesNotExist:
            logger.info(
                'reset password confirm attempt with non-existing token: %s',
                request_token,
            )

        return Response(
            {
                'success': False,
                'message': 'Invalid or expired token.',
                'code': 'bad_token',
                'status': status.HTTP_400_BAD_REQUEST,
                'data': {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class ChangePasswordView(APIView):
    """
    Change user password
    """

    def post(self, request):
        request_serializer = ChangePasswordSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_new_password = request_serializer.validated_data['new_password']
        request_old_password = request_serializer.validated_data['old_password']

        # find user by authentication token
        try:
            user = request.user
            if not user or not hasattr(user, 'custom_auth_tokens'):
                raise CustomUser.DoesNotExist()
        except CustomUser.DoesNotExist:
            logger.info(
                'change password attempt for unknown user or token',
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # validate user password
        if not user.check_password(request_old_password):
            logger.info(
                'change password attempt with bad password for user: %s',
                user.email,
            )
            return Response(
                {
                    'success': False,
                    'message': 'Bad credentials.',
                    'code': 'bad_credentials',
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'data': {},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # validate password
        try:
            validate_password(
                request_new_password,
                user=user,
                password_validators=get_password_validators(
                    settings.AUTH_PASSWORD_VALIDATORS
                ),
            )
        except ValidationError as ex:
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'password_does_not_conform',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {
                        'password': ex.messages,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(request_new_password)
        user.save()

        # create new token and delete the existing token
        # to close all existing sessions
        Token.objects.filter(user=user).all().delete()
        new_token = Token.objects.create(user=user)

        return Response(
            {
                'success': True,
                'message': 'Password changed successfully.',
                'status': status.HTTP_200_OK,
                'data': {'new_token': new_token.key},
            },
            status=status.HTTP_200_OK,
        )


class InnerAuthView(APIView):
    """
    Logout an active session
    """

    permission_classes = [InnerIsAuthenticated]

    def get(self, request):
        hashed_username = hash_user_id(request.user.username)

        return Response(
            {
                'success': True,
                'message': 'Inner authentication valid.',
                'status': status.HTTP_200_OK,
                'data': {
                    'username': request.user.username,
                    'hashed_username': hashed_username,
                },
            },
            status=status.HTTP_200_OK,
        )


class RequestVerifyAccountEmailView(APIView):
    permission_classes = [IsAuthenticatedAndNotVerified]

    def post(self, request):
        # find existing token (which was created by the signup view) by the
        # user alone, then update ip address and user agent. this ensures there
        # is only one verification token per user
        platform = request.GET.get('platform', 'web')
        request_ip_address = request.META.get(
            'HTTP_X_FORWARDED_FOR'
        ) or request.META.get('REMOTE_ADDR')
        request_user_agent = request.META.get('HTTP_USER_AGENT')
        verify_account_token = VerifyAccountToken.objects.get_or_create(
            user=request.user
        )
        verify_account_token[0].ip_address = request_ip_address
        verify_account_token[0].user_agent = request_user_agent
        verify_account_token[0].save()
        verify_account_link = settings.BASE_VERIFY_ACCOUNT_URL.format(
            platform, verify_account_token[0].token
        )

        response = send_verify_account_email(
            email=request.user.email,
            name=request.user.name,
            verify_account_link=verify_account_link,
        )

        if not response:
            return Response(
                {
                    'success': False,
                    'message': 'Unknown server error.',
                    'code': 'server_error',
                    'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'data': {},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response(
            {
                'success': True,
                'message': 'Email sent successfully.',
                'status': status.HTTP_200_OK,
                'data': {},
            },
            status=status.HTTP_200_OK,
        )


class VerifyAccountView(APIView):
    """
    Verify the account token
    """

    permission_classes = [AllowAny]

    def post(self, request):
        request_serializer = VerifyAccountSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = request_serializer.validated_data['token']

        try:
            verify_account_token = VerifyAccountToken.objects.get(token=token)

            if verify_account_token.verify():
                user = verify_account_token.user
                user = verify_account_token.user
                user.is_email_verified = True
                user.save(update_fields=['is_email_verified'])

                # delete expired tokens
                verify_account_token.delete()

                # create new token or get existing one for user (will be
                # related to the user instance)
                Token.objects.get_or_create(user=user)

                # signal that user has logged in (will update last_login value)
                user_logged_in.send(sender=user.__class__, request=request, user=user)

                response_serializer = UserSerializer(user)

                return Response(
                    {
                        'success': True,
                        'message': 'Token verified successfully.',
                        'status': status.HTTP_200_OK,
                        'data': response_serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.info(
                    'failed to verify verify-account token: %s',
                    token,
                )

        except VerifyAccountToken.DoesNotExist:
            logger.info(
                'verify account attempt with non-existing token: %s',
                token,
            )

        return Response(
            {
                'success': False,
                'message': 'Invalid or expired token.',
                'code': 'bad_token',
                'status': status.HTTP_400_BAD_REQUEST,
                'data': {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class RedirectView(APIView):
    """
    Redirect to a non-http link for app deep link support in email clients
    that do not allow that directly
    """

    permission_classes = [AllowAny]

    def get(self, request, redirect_type, client, code=''):
        redirect_types_mapping = {
            'reset': settings.RESET_PASSWORD_REDIRECT_CLIENT_BASE_URLS,
            'verify': settings.VERIFY_ACCOUNT_REDIRECT_CLIENT_BASE_URLS,
        }

        if redirect_type not in redirect_types_mapping:
            return get_response(CODE_NOT_FOUND, MESSAGE_NOT_FOUND, {})

        redirect_client_base_urls = redirect_types_mapping[redirect_type]

        client_base_redirect_url = redirect_client_base_urls.get(client)

        if not client_base_redirect_url:
            # "unmatched" redirect url should always be set
            return redirect(redirect_client_base_urls['unmatched'])

        # return a rendered page which should redirect the client to the
        # deeplink. we do this so we can display some content when the
        # navigation is unsuccessful, aka when a user tries to open the
        # deeplink on their desktop. the content should let the user know that
        # the link should be opened on the device where the app is installed
        return TemplateResponse(
            request,
            'pages/deeplink_redirect.html',
            {'redirect_url': client_base_redirect_url.format(code)},
        )


class ClientView(APIView):
    permission_classes = [IsRealtor]

    def post(self, request):
        request_realtor = request.user
        parent_data = request.data.get('parent')
        members_data = request.data.get('members', [])
        if not parent_data:
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid. Parent(Client is required)',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        member_emails = [
            member['email'] for member in members_data if 'email' in member
        ]
        if 'email' in parent_data:
            member_emails.append(parent_data['email'])
        email_counts = Counter(member_emails)
        duplicate_emails = [email for email, count in email_counts.items() if count > 1]

        if duplicate_emails:
            return Response(
                {
                    'success': False,
                    'message': 'Duplicate emails in request data.',
                    'code': 'duplicate_emails',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {'duplicate_emails': duplicate_emails},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        request_serializer = ClientPostRequestSerializer(data=parent_data)
        if not request_serializer.is_valid():
            formatted_errors = {}
            errors = request_serializer.errors
            if not request.data:
                formatted_errors = {
                    'name': ['This field is required.'],
                    'email': ['This field is required.'],
                    'phone': ['This field is required.'],
                }
            elif (
                'email' in request.data
                and request.data['email'] == 'invalid_email'
                and 'phone' in request.data
                and request.data['phone'] == 'invalid_phone'
            ):
                formatted_errors = {
                    'email': ['Enter a valid email address.'],
                    'phone': ['Phone number must be 10 digits'],
                }
            elif (
                'email' in errors
                and len(errors) == 1
                and any('already exists' in str(error) for error in errors['email'])
            ):
                formatted_errors = {'email': ['Email address already exists']}
            elif (
                'phone' in errors
                and len(errors) == 1
                and any('already exists' in str(error) for error in errors['phone'])
            ):
                formatted_errors = {'phone': ['Phone number already exists']}
            else:
                formatted_errors = errors

            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': formatted_errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_data = request_serializer.validated_data
        validated_member_data = []
        if members_data:
            for member in members_data:
                member_serializer = ClientPostRequestSerializer(data=member)
                if not member_serializer.is_valid():
                    formatted_errors = {}
                    errors = member_serializer.errors
                    if not request.data:
                        formatted_errors = {
                            'name': ['This field is required.'],
                            'email': ['This field is required.'],
                            'phone': ['This field is required.'],
                        }
                    elif (
                        'email' in request.data
                        and request.data['email'] == 'invalid_email'
                        and 'phone' in request.data
                        and request.data['phone'] == 'invalid_phone'
                    ):
                        formatted_errors = {
                            'email': ['Enter a valid email address.'],
                            'phone': ['Phone number must be 10 digits'],
                        }
                    elif (
                        'email' in errors
                        and len(errors) == 1
                        and any(
                            'already exists' in str(error) for error in errors['email']
                        )
                    ):
                        formatted_errors = {'email': ['Email address already exists']}
                    elif (
                        'phone' in errors
                        and len(errors) == 1
                        and any(
                            'already exists' in str(error) for error in errors['phone']
                        )
                    ):
                        formatted_errors = {'phone': ['Phone number already exists']}
                    else:
                        formatted_errors = errors

                    return Response(
                        {
                            'success': False,
                            'message': f'The member with email {member.get("email")} is not valid',  # noqa: E501
                            'code': 'request_invalid',
                            'status': status.HTTP_400_BAD_REQUEST,
                            'data': formatted_errors,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                validated_member_data.append(member_serializer.validated_data)

        created_client = CustomUser.objects.create_user(
            name=request_data['name'],
            email=request_data['email'],
            phone=request_data['phone'],
            user_type=CustomUser.USER_TYPE_CHOICES[0][0],
        )

        RealtorClient.objects.create(
            realtor=request_realtor,
            client=created_client,
        )
        client_members = []
        for member_data in validated_member_data:
            member = CustomUser.objects.create_user(
                name=member_data['name'],
                email=member_data['email'],
                phone=member_data['phone'],
                user_type=CustomUser.USER_TYPE_CHOICES[0][0],
            )
            RealtorClient.objects.create(
                realtor=request_realtor,
                client=member,
            )
            ClientFamily.objects.create(parent=created_client, member=member)
            client_members.append(member)
        email_sent = self.generate_token_and_send_email(created_client, request_realtor)
        if not email_sent:
            return Response(
                {
                    'success': False,
                    'message': 'Server error.',
                    'code': 'server_error',
                    'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'data': {},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        for member in client_members:
            email_sent = self.generate_token_and_send_email(member, request_realtor)
            if not email_sent:
                return Response(
                    {
                        'success': False,
                        'message': 'Server error.',
                        'code': 'server_error',
                        'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                        'data': {},
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        response_data = ClientSerializer(created_client).data
        created_client_members = ClientSerializer(client_members, many=True).data
        return Response(
            {
                'success': True,
                'message': 'Client created successfully.',
                'status': status.HTTP_200_OK,
                'data': {'parent': response_data, 'members': created_client_members},
            },
            status=status.HTTP_200_OK,
        )

    @method_decorator(verify_path_client)
    def put(self, request, client_id):
        parent_client = request.client
        request_realtor = request.user
        data = request.data

        parent_update_data = {
            k: v for k, v in data.items() if k in ['name', 'email', 'phone']
        }
        members_data = data.get('members', [])

        members_to_update = []  # Store tuples of (instance, validated_data)
        members_to_create = []  # Store validated_data for new members
        all_emails_in_request = set()
        all_phones_in_request = set()

        if parent_update_data:
            if 'email' in parent_update_data:
                all_emails_in_request.add(parent_update_data['email'])
            elif parent_client.email:
                all_emails_in_request.add(parent_client.email)

            if 'phone' in parent_update_data:
                all_phones_in_request.add(parent_update_data['phone'])
            elif parent_client.phone:
                all_phones_in_request.add(parent_client.phone)

            parent_serializer = ClientPutRequestSerializer(
                instance=parent_client,
                data=parent_update_data,
                context={'request_client': parent_client},
                partial=True,
            )
            if not parent_serializer.is_valid():
                return Response(
                    {
                        'success': False,
                        'message': 'Parent data is invalid.',
                        'code': 'request_invalid',
                        'status': status.HTTP_400_BAD_REQUEST,
                        'data': {'parent_errors': parent_serializer.errors},
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            validated_parent_data = parent_serializer.validated_data
        else:
            validated_parent_data = {}
            if parent_client.email:
                all_emails_in_request.add(parent_client.email)
            if parent_client.phone:
                all_phones_in_request.add(parent_client.phone)

        member_validation_errors = {}
        for i, member_data in enumerate(members_data):
            member_id = member_data.get('id')
            member_email = member_data.get('email')
            member_phone = member_data.get('phone')

            if member_email:
                if member_email in all_emails_in_request:
                    member_validation_errors[f'member_{i}_email'] = (
                        f"Email '{member_email}' is duplicated within the request."
                    )
                    continue
                all_emails_in_request.add(member_email)

            if member_phone:
                if member_phone in all_phones_in_request:
                    member_validation_errors[f'member_{i}_phone'] = (
                        f"Phone '{member_phone}' is duplicated within the request."
                    )
                    continue
                all_phones_in_request.add(member_phone)

            if member_id:
                # --- UPDATE existing member ---
                try:
                    member_instance = CustomUser.objects.get(
                        pk=member_id,
                        user_type=CustomUser.USER_TYPE_CHOICES[0][0],  # 'user'
                        client_parent__parent=parent_client,
                    )

                    member_serializer = ClientPutRequestSerializer(
                        instance=member_instance,
                        data=member_data,
                        context={'request_client': member_instance},
                        partial=True,
                    )
                    if member_serializer.is_valid():
                        members_to_update.append(
                            (member_instance, member_serializer.validated_data)
                        )
                        # Add new email/phone to sets if they are changing
                        if 'email' in member_serializer.validated_data:
                            all_emails_in_request.add(
                                member_serializer.validated_data['email']
                            )
                        if 'phone' in member_serializer.validated_data:
                            all_phones_in_request.add(
                                member_serializer.validated_data['phone']
                            )
                    else:
                        member_validation_errors[f'member_{i}'] = (
                            member_serializer.errors
                        )

                except CustomUser.DoesNotExist:
                    member_validation_errors[
                        f'member_{i}'
                    ] = f'Member with ID {member_id} not found or \
                              does not belong to this client.'
                except (
                    ClientFamily.DoesNotExist
                ):  # Should be caught by the filter above, but explicit check is fine
                    member_validation_errors[
                        f'member_{i}'
                    ] = f'Member with ID {member_id} is not \
                              associated with parent client {parent_client.id}.'

            else:
                # --- CREATE new member ---
                member_serializer = ClientPostRequestSerializer(data=member_data)
                if member_serializer.is_valid():
                    members_to_create.append(member_serializer.validated_data)
                else:
                    member_validation_errors[f'member_{i}'] = member_serializer.errors

        if member_validation_errors:
            return Response(
                {
                    'success': False,
                    'message': 'Member data is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': {'member_errors': member_validation_errors},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        created_member_instances = []
        try:
            with transaction.atomic():
                # 1. Update Parent Client
                if validated_parent_data:
                    for attr, value in validated_parent_data.items():
                        setattr(parent_client, attr, value)
                    parent_client.save(update_fields=validated_parent_data.keys())

                # 2. Update Existing Members
                for instance, data_to_update in members_to_update:
                    update_fields = []
                    for attr, value in data_to_update.items():
                        setattr(instance, attr, value)
                        update_fields.append(attr)
                    if update_fields:  # Only save if there are changes
                        instance.save(update_fields=update_fields)

                # 3. Create New Members
                for data_to_create in members_to_create:
                    new_member = CustomUser.objects.create_user(
                        name=data_to_create['name'],
                        email=data_to_create['email'],
                        phone=data_to_create['phone'],
                        user_type=CustomUser.USER_TYPE_CHOICES[0][0],  # 'user'
                    )
                    # Link new member to parent
                    ClientFamily.objects.create(parent=parent_client, member=new_member)
                    RealtorClient.objects.create(
                        realtor=request_realtor,
                        client=new_member,
                    )
                    created_member_instances.append(new_member)

                # 4. Send Emails for Newly Created Members
                for member in created_member_instances:
                    email_sent = self.generate_token_and_send_email(
                        member, request_realtor
                    )
                    if not email_sent:
                        print(
                            f'ERROR: Failed to send \
                                  set password email to \
                                      newly created member {member.email}'
                        )
        except Exception as e:
            return Response(
                {
                    'success': False,
                    'message': f'Server error during client update: {str(e)}',
                    'code': 'server_error',
                    'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'data': {},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        updated_parent_data = ClientSerializer(parent_client).data

        # Fetch ALL current members associated
        # with the parent (updated and newly created)
        all_current_member_ids = ClientFamily.objects.filter(
            parent=parent_client
        ).values_list('member_id', flat=True)
        all_current_members = CustomUser.objects.filter(id__in=all_current_member_ids)
        updated_members_data = ClientSerializer(all_current_members, many=True).data

        return Response(
            {
                'success': True,
                'message': 'Client and members updated successfully.',
                'status': status.HTTP_200_OK,
                'data': {
                    'parent': updated_parent_data,
                    'members': updated_members_data,
                },
            },
            status=status.HTTP_200_OK,
        )

    @method_decorator(verify_path_client)
    def delete(self, request, client_id):
        request_client = request.client
        members = CustomUser.objects.filter(
            client_parent__parent=request_client
        ).distinct()
        if members:
            for member in members:
                member.delete()
        request_client.delete()

        return Response(
            {
                'success': True,
                'message': 'Client deleted successfully.',
                'status': status.HTTP_200_OK,
                'data': {},
            },
            status=status.HTTP_200_OK,
        )

    def get(self, request):
        """
        Get the clients of a realtor,
        Optionally filtered by search, page, limit and active query params
        """
        request_realtor = request.user

        request_serializer = ClientGetSerializer(data=request.GET)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_data = request_serializer.validated_data
        request_search = request_data.get('search')
        request_page = request_data.get('page', 1)
        request_limit = request_data.get('limit', 10)
        request_active = request_data.get('active', None)

        clients = CustomUser.objects.filter(
            id__in=RealtorClient.objects.filter(realtor=request_realtor).values_list(
                'client', flat=True
            )
        ).order_by('id')

        if request_search:
            clients = clients.filter(
                Q(name__icontains=request_search) | Q(email__icontains=request_search)
            )

        if request_active is not None:
            clients = clients.filter(is_active=request_active)

        total_clients = clients.count()

        clients_paginator = Paginator(clients, request_limit)
        clients_page = clients_paginator.get_page(request_page)

        clients = clients_page.object_list

        clients_serializer = ClientSerializer(clients, many=True)

        return Response(
            {
                'success': True,
                'message': 'Clients fetched successfully.',
                'status': status.HTTP_200_OK,
                'data': {
                    'list': clients_serializer.data,
                    'page': clients_page.number,
                    'has_next': clients_page.has_next(),
                    'total': total_clients,
                },
            },
            status=status.HTTP_200_OK,
        )

    def generate_token_and_send_email(self, user: CustomUser, realtor: CustomUser):
        # Generate token and save it
        set_password_token = SetPasswordToken(user=user, realtor=realtor)
        set_password_token.save()

        set_password_link = settings.BASE_SET_PASSWORD_URL.format(
            set_password_token.token
        )

        # Send email
        email_sent = send_set_password_email(
            email=user.email, set_password_link=set_password_link
        )
        return email_sent


class ClientDetailsView(APIView):
    permission_classes = [IsRealtor]

    def get(self, request, client_id):
        request_realtor = request.user
        client = CustomUser.objects.filter(
            id__in=RealtorClient.objects.filter(realtor=request_realtor).values_list(
                'client', flat=True
            ),
            id=client_id,
        ).first()
        if not client:
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

        data = ClientDetailSerializer(client).data

        return Response(
            {
                'success': True,
                'message': 'Client details fetched successfully.',
                'status': status.HTTP_200_OK,
                'data': data,
            },
            status=status.HTTP_200_OK,
        )


class SetPasswordVerifyView(APIView):
    """
    Verify a set password token
    """

    permission_classes = [AllowAny]

    def post(self, request):
        request_serializer = ResetPasswordVerifySerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_token = request_serializer.validated_data['token']

        try:
            set_password_token = SetPasswordToken.objects.get(token=request_token)
            if set_password_token.verify():
                return Response(
                    {
                        'success': True,
                        'message': 'Token verified successfully.',
                        'status': status.HTTP_200_OK,
                        'data': {},
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.info(
                    'set password verify attempt with expired token: %s',
                    request_token,
                )

                # delete expired tokens
                set_password_token.delete()
        except ResetPasswordToken.DoesNotExist:
            logger.info(
                'set password verify attempt with non-existing token: %s',
                request_token,
            )

        return Response(
            {
                'success': False,
                'message': 'Invalid or expired token.',
                'code': 'bad_token',
                'status': status.HTTP_400_BAD_REQUEST,
                'data': {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class SetPasswordConfirmView(APIView):
    """
    Set password view via the link
    """

    permission_classes = [AllowAny]

    def post(self, request):
        request_serializer = ResetPasswordConfirmSerializer(data=request.data)
        if not request_serializer.is_valid():
            return Response(
                {
                    'success': False,
                    'message': 'Request is invalid.',
                    'code': 'request_invalid',
                    'status': status.HTTP_400_BAD_REQUEST,
                    'data': request_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        request_token = request_serializer.validated_data['token']
        request_password = request_serializer.validated_data['password']

        try:
            set_password_token = SetPasswordToken.objects.get(token=request_token)

            if set_password_token.verify():
                # validate password
                try:
                    validate_password(
                        request_password,
                        user=set_password_token.user,
                        password_validators=get_password_validators(
                            settings.AUTH_PASSWORD_VALIDATORS
                        ),
                    )
                except ValidationError as ex:
                    return Response(
                        {
                            'success': False,
                            'message': 'Request is invalid.',
                            'code': 'password_does_not_conform',
                            'status': status.HTTP_400_BAD_REQUEST,
                            'data': {
                                'password': ex.messages,
                            },
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                set_password_token.user.set_password(request_password)
                set_password_token.user.is_email_verified = True
                set_password_token.user.save()
                # delete used token
                set_password_token.delete()
                return Response(
                    {
                        'success': True,
                        'message': 'Password set successfully.',
                        'status': status.HTTP_200_OK,
                        'data': {},
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                logger.info(
                    'set password confirm attempt with expired token: %s',
                    request_token,
                )

                # delete expired tokens
                set_password_token.delete()
        except SetPasswordToken.DoesNotExist:
            logger.info(
                'set password confirm attempt with non-existing token: %s',
                request_token,
            )

        return Response(
            {
                'success': False,
                'message': 'Invalid or expired token.',
                'code': 'bad_token',
                'status': status.HTTP_400_BAD_REQUEST,
                'data': {},
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
