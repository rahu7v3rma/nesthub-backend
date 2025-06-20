import logging

from django_otp.plugins.otp_email.models import EmailDevice


logger = logging.getLogger(__name__)


def send_otp(user):
    try:
        device, created = EmailDevice.objects.get_or_create(user=user, name='default')
        device.generate_challenge({'extra_context': user.name})
        return True
    except Exception as e:
        logger.error(f'Failed to send OTP for user {user.email}: {e}')
        return False


def verify_otp(user, otp):
    try:
        device = EmailDevice.objects.get(user=user, name='default')
        if device.verify_token(otp):
            return True
        return False
    except Exception as e:
        logger.error(f'Failed to verify OTP for user {user.email}: {e}')
        return False
