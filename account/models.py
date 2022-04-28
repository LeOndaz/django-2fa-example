from django.contrib.auth.hashers import make_password
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager as BaseUserManager
import pyotp
import random
import uuid
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from django.utils.translation import gettext_lazy as _
from django.apps import apps
import base64

def generate_otp():
    return ''.join(str(random.randint(0, 9)) for i in range(6))


class UserManager(BaseUserManager):
    def _create_user(self, phone_number, email, password, **extra_fields):
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
        user = self.model(phone_number=phone_number, email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, phone_number, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, phone_number, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault('first_name', 'Superuser')

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(phone_number, email, password, **extra_fields)


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
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    totp_hash = models.UUIDField(default=uuid.uuid4)
    phone_number = PhoneNumberField(unique=True)
    two_factor_enabled = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = 'phone_number'

    def totp(self):
        return pyotp.TOTP(self.totp_hash).now()

    def verify_totp(self, otp):
        b32_hash = base64.b32encode(str(self.totp_hash).encode('utf-8')).decode('utf-8')
        print(b32_hash)
        return pyotp.TOTP(b32_hash).verify(otp)

    def send_sms(self, from_, content):
        print(content)

    def get_qr_content(self):
        return "otpauth://totp/site:{email}?secret={hash}&issuer=site".format(
            email=self.email,
            hash=self.totp_hash,
        )


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, default=generate_otp)  # control OTP length here

    issued_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def expire(self):
        self.is_used = True
        self.save()

    def is_expired(self):
        return self.is_used or self.issued_at >= timezone.now()

    def __str__(self):
        return self.code
