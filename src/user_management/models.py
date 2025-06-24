import binascii
import os

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, UserManager
from django.contrib.auth.tokens import default_token_generator
from django.db import models

from lib.utils import CustomVerifyAccountTokenGenerator


# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')

        return self.create_user(email, password, **extra_fields)


# Custom User Model
class CustomUser(AbstractBaseUser):
    USER_TYPE_CHOICES = [
        ('user', 'User'),
        ('realtor', 'Realtor'),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    license_id = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)
    user_type = models.CharField(
        max_length=10, choices=USER_TYPE_CHOICES, default='realtor'
    )
    address = models.TextField(blank=True, null=True)
    password = models.CharField(max_length=128)
    region = models.CharField(max_length=128, default=None, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(default=None, null=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    is_superuser = models.BooleanField(default=False)
    otp_exempt = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    profile_pic = models.ImageField(
        upload_to='profile_pictures/', null=True, blank=True
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        """
        Does the user have a specific permission?
        """
        return self.is_superuser

    def has_module_perms(self, app_label):
        """
        Does the user have permissions to view the app `app_label`?
        """
        return self.is_superuser


class CustomToken(models.Model):
    key = models.CharField(max_length=40, primary_key=True)
    user = models.ForeignKey(
        CustomUser,
        related_name='custom_auth_tokens',  # Change the related_name to avoid conflict
        on_delete=models.CASCADE,
        verbose_name='User',
    )
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.make_random_key()
        super().save(*args, **kwargs)

    @staticmethod
    def make_random_key():
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key


# Token Generators
TOKEN_GENERATOR = default_token_generator
VERIFY_ACCOUNT_TOKEN_GENERATOR = CustomVerifyAccountTokenGenerator()


# Reset Password Token Model
class ResetPasswordToken(models.Model):
    class Meta:
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'

    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        CustomUser,
        related_name='password_reset_tokens',
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    token = models.CharField(max_length=255, db_index=True, unique=True)
    ip_address = models.GenericIPAddressField(default='', blank=True, null=True)
    user_agent = models.CharField(max_length=256, default='', blank=True)

    def _generate_token(self):
        return TOKEN_GENERATOR.make_token(self.user)

    def verify(self):
        return TOKEN_GENERATOR.check_token(self.user, self.token)

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self._generate_token()
        return super().save(*args, **kwargs)


class SetPasswordToken(models.Model):
    class Meta:
        verbose_name = 'Set Password Token'
        verbose_name_plural = 'Set Password Tokens'

    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        CustomUser,
        related_name='set_password_tokens',
        on_delete=models.CASCADE,
    )
    realtor = models.ForeignKey(
        CustomUser,
        related_name='set_password_client_tokens',
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    token = models.CharField(max_length=255, db_index=True, unique=True)

    def _generate_token(self):
        return TOKEN_GENERATOR.make_token(self.user)

    def verify(self):
        return TOKEN_GENERATOR.check_token(self.user, self.token)

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self._generate_token()
        return super().save(*args, **kwargs)


# Verify Account Token Model
class VerifyAccountToken(models.Model):
    class Meta:
        verbose_name = 'Verify Account Token'
        verbose_name_plural = 'Verify Account Tokens'

    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        CustomUser,
        related_name='verify_account_tokens',
        on_delete=models.CASCADE,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    token = models.CharField(max_length=255, db_index=True, unique=True)
    ip_address = models.GenericIPAddressField(default='', blank=True, null=True)
    user_agent = models.CharField(max_length=256, default='', blank=True)

    def _generate_token(self):
        return VERIFY_ACCOUNT_TOKEN_GENERATOR.make_token(self.user)

    def verify(self):
        return VERIFY_ACCOUNT_TOKEN_GENERATOR.check_verify_account_token(
            self.user, self.token
        )

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self._generate_token()
        return super().save(*args, **kwargs)


# Proxy Models for Admin and Customer
class AdminManager(UserManager):
    def get_queryset(self):
        return super().get_queryset().filter(is_staff=True)


class Admin(CustomUser):
    objects = AdminManager()

    class Meta:
        proxy = True


class CustomerManager(UserManager):
    def get_queryset(self):
        return super().get_queryset().filter(is_staff=False, is_active=True)


class Customer(CustomUser):
    objects = CustomerManager()

    class Meta:
        proxy = True


# Realtor-Client Relationship Model
class RealtorClient(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    realtor = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='realtor_clients'
    )
    client = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='client_realtors'
    )


class ClientFamily(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    parent = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='client_families'
    )
    member = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='client_parent'
    )
