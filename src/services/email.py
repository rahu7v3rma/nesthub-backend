import logging
import os
from typing import Optional, Union

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template


logger = logging.getLogger(__name__)


def send_mail(
    send_to: list,
    subject: str,
    message: Optional[str] = None,
    from_email: Optional[str] = settings.DEFAULT_FROM_EMAIL,
    reply_to: Optional[list[str]] = None,
    context: Optional[dict] = None,
    cc_emails: Optional[list[str]] = None,
    bcc_emails: Optional[list[str]] = None,
    attachments: Optional[list[Union[str, bytes, Optional[str]]]] = None,
    plaintext_email_template: Optional[Union[str, bytes, os.PathLike]] = None,
    html_email_template: Optional[Union[str, bytes, os.PathLike]] = None,
    fail_silently: Optional[bool] = False,
):
    if reply_to is None:
        reply_to = [settings.REPLY_TO_EMAIL]
    if attachments is None:
        attachments = []
    if context is None:
        context = {}
    if cc_emails is None:
        cc_emails = []
    if bcc_emails is None:
        bcc_emails = []

    if plaintext_email_template:
        text_content = get_template(plaintext_email_template).render(context)
    else:
        text_content = message

    msg = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=from_email,
        to=send_to,
        cc=cc_emails,
        bcc=bcc_emails,
        reply_to=reply_to,
    )

    if html_email_template:
        html_content = get_template(html_email_template).render(context)
        msg.attach_alternative(html_content, 'text/html')
        msg.content_subtype = 'html'

    for attachment in attachments:
        msg.attach(
            attachment['filename'],
            attachment['content'],
            attachment['mimetype'],
        )

    try:
        msg.send(fail_silently=fail_silently)
        return True
    except Exception as error:
        message = f'Failed sending email [{subject}] to {send_to} error: {error}'
        logger.error(
            message,
            exc_info=True,
            extra={
                'email': message,
                'error': error,
            },
        )
        return False


def send_reset_password_email(email: str, reset_password_link: str):
    context = {'reset_password_link': reset_password_link}
    res = send_mail(
        [email],
        'Reset your password',
        context=context,
        plaintext_email_template='emails/reset_password.txt',
        html_email_template='emails/reset_password.html',
    )
    return res


def send_set_password_email(email: str, set_password_link: str):
    context = {'set_password_link': set_password_link}
    res = send_mail(
        [email],
        'Set your password',
        context=context,
        plaintext_email_template='emails/set_password.txt',
        html_email_template='emails/set_password.html',
    )
    return res


def send_verify_account_email(email: str, name: str, verify_account_link: str):
    context = {'name': name, 'verify_account_link': verify_account_link}
    res = send_mail(
        [email],
        'Verify your email for the NH',
        context=context,
        plaintext_email_template='emails/verify_account.txt',
        html_email_template='emails/verify_account.html',
    )
    return res
