from django import forms
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from phonenumber_field.formfields import PhoneNumberField

User = get_user_model()


class RegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "password1", "password2"]


class OTPForm(forms.Form):
    code = forms.CharField(max_length=6)


class TwoFactorForm(forms.Form):
    choices = [
        (
            "sms",
            "SMS",
        ),
        (
            "authenticator",
            "Authenticator",
        ),
    ]

    auth_method = forms.ChoiceField(choices=choices, widget=forms.RadioSelect)


class LoginForm(forms.Form):
    email = forms.EmailField()

    password = forms.CharField(
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    def __init__(self, request, *args, **kwargs):
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email is not None and password:
            self.user_cache = authenticate(email=email, password=password)

            if self.user_cache is None:
                raise ValidationError("Incorrect email or password.")

        return self.cleaned_data

    def get_user(self):
        return self.user_cache


class UserSettingsForm(forms.Form):
    enable_2fa = forms.BooleanField(required=False, initial=False)
    phone_number = PhoneNumberField(required=False, initial=None)
