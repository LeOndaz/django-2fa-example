from django.contrib.auth.hashers import make_password
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    UserManager as BaseUserManager,
)
import pyotp
import random
import uuid
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from django.utils.translation import gettext_lazy as _
from django.apps import apps
import base64
from .utils import send_sms
from django.core.mail import send_mail
import string


def generate_otp():
    return "".join(str(random.randint(0, 9)) for i in range(6))


def generate_hash():
    u = str(uuid.uuid4())
    random_chars = "".join(random.choices(string.ascii_lowercase, k=100))

    return u + random_chars


class UserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        email = self.normalize_email(email)
        # Lookup the real model class from the global app registry so this
        # manager method can be used in migrations. This is fine because
        # managers are by definition working on the real model.
        GlobalUserModel = apps.get_model(
            self.model._meta.app_label, self.model._meta.object_name
        )
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("first_name", "Superuser")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class User(PermissionsMixin, AbstractBaseUser):
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = models.EmailField(_("email address"), unique=True)

    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=False,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    _totp_hash = models.CharField(
        default=generate_hash(), db_column="totp_hash", max_length=256
    )
    phone_number = PhoneNumberField(unique=True, blank=True, null=True)
    two_factor_enabled = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    @property
    def totp_hash(self):
        return base64.b32encode(self._totp_hash.encode("utf-8")).decode("utf-8").replace('=', '')

    def totp(self):
        return pyotp.TOTP(self.totp_hash).now()

    def verify_totp(self, otp):
        return pyotp.TOTP(self.totp_hash).verify(otp)

    def send_sms(self, from_, content):
        send_sms(from_, self.phone_number, content)

    def send_mail(self, subject, from_, content):
        send_mail(subject, content, from_, [self.email], fail_silently=True)

    def get_qr_content(self):
        return "otpauth://totp/AuthApp?secret={}".format(self.totp_hash)

    def __str__(self):
        return self.email


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(
        max_length=6, default=generate_otp
    )  # control OTP length here

    issued_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def expire(self):
        self.is_used = True
        self.save()

    def is_expired(self):
        return self.is_used or self.issued_at >= timezone.now()

    def __str__(self):
        return self.code
