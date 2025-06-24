# pylint: disable=invalid-name

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int


def get_realtor_property_id_for_user(obj, request, client_id=None):
    """
    Get realtor_property_id for a property based on user type and context.
    """
    # avoid circular import
    from user_management.models import ClientFamily

    realtor_property_id = getattr(obj, 'realtor_property_id', None)
    if realtor_property_id:
        return realtor_property_id

    if not request or not request.user:
        return None

    if request.user.user_type == 'realtor':
        client_id = client_id or request.GET.get('user_id')
        if client_id:
            realtor_property = obj.realtor_properties.filter(
                realtor=request.user, client_id=client_id
            ).first()
            return realtor_property.id if realtor_property else None
    else:
        client = request.user
        client_family = ClientFamily.objects.filter(member=request.user).first()
        if client_family:
            client = client_family.parent

        realtor_property = obj.realtor_properties.filter(client=client).first()
        return realtor_property.id if realtor_property else None

    return None


class CustomVerifyAccountTokenGenerator(PasswordResetTokenGenerator):
    def check_verify_account_token(self, user, token):
        """
        Check that a password reset token is correct for a given user
        witout expiration.
        """
        if not (user and token):
            return False
        # Parse the token
        try:
            ts_b36, _ = token.split('-')
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        for secret in [self.secret, *self.secret_fallbacks]:
            if constant_time_compare(
                self._make_token_with_timestamp(user, ts, secret),
                token,
            ):
                break
        else:
            return False

        return True

    def _make_hash_value(self, user, timestamp):
        """
        create a hash for the token. ignore the last login time as the user
        can technically login before verifying the account. based on the base
        class implementation
        """
        email_field = user.get_email_field_name()
        email = getattr(user, email_field, '') or ''
        return f'{user.pk}{timestamp}{email}'
