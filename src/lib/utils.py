# pylint: disable=invalid-name

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int


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
