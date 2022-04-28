from django.core.exceptions import ValidationError
from django.shortcuts import render, HttpResponseRedirect, reverse
from django.http.response import HttpResponseForbidden
from django.urls import reverse_lazy
from django.views.generic import FormView, CreateView, RedirectView
from django.contrib.auth.views import LoginView as BaseLoginView, LogoutView  # imported for convenience
from django.contrib.auth import get_user_model, login
from .forms import RegistrationForm, LoginForm, TwoFactorForm, OTPForm, UserSettingsForm
from .models import OTP
from django.contrib.auth.mixins import LoginRequiredMixin

User = get_user_model()


def get_user_from_session(session):
    user_id = session.get('user_id')

    if user_id:
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def home(request):
    return render(request, 'home.html')


class LoginView(BaseLoginView):
    form_class = LoginForm
    template_name = 'form.html'

    def form_valid(self, form):
        """
        Save the user ID in the session if the form is valid.
        """

        user = form.get_user()
        user_id = user.pk
        self.request.session['user_id'] = user_id

        if user.two_factor_enabled:
            return HttpResponseRedirect(reverse('two-factor'))

        login(self.request, user)
        return super().form_valid(form)


class TwoFactorView(FormView):
    form_class = TwoFactorForm
    template_name = 'form.html'

    def dispatch(self, request, *args, **kwargs):
        if get_user_from_session(request.session) is None:
            return HttpResponseForbidden()

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = get_user_from_session(self.request.session)
        auth_method = form.cleaned_data['auth_method']

        if auth_method == 'sms':
            message = 'Your OTP code is {}'
            otp = OTP.objects.create(user=user)
            user.send_sms(..., message.format(otp))
            return HttpResponseRedirect(reverse('otp'))

        return HttpResponseRedirect(reverse('totp'))


class OTPView(TwoFactorView):
    form_class = OTPForm

    def form_valid(self, form):
        code = form.cleaned_data['code']
        user = get_user_from_session(self.request.session)

        try:
            otp = OTP.objects.get(user=user, code=code)
        except OTP.DoesNotExist:
            raise ValidationError('Invalid OTP')

        if otp.is_expired():
            raise ValidationError('Invalid or expired OTP')

        otp.expire()
        login(self.request, user)

        return HttpResponseRedirect(reverse('home'))


class TOTPView(OTPView):
    def form_valid(self, form):
        code = form.cleaned_data['code']
        user = get_user_from_session(self.request.session)

        if not user.verify_totp(code):
            raise ValidationError('Invalid OTP')

        login(self.request, user)
        return HttpResponseRedirect(reverse('home'))


class LoginSuccessView(RedirectView):
    url = reverse_lazy('home')


class SignUpView(CreateView):
    template_name = 'form.html'
    success_url = reverse_lazy('login')
    form_class = RegistrationForm


class UserSettingsView(LoginRequiredMixin, FormView):
    form_class = UserSettingsForm
    template_name = 'form.html'

    def form_valid(self, form):
        enable_2fa = form.cleaned_data['enable_2fa']
        print(enable_2fa)
        self.request.user.two_factor_enabled = enable_2fa
        self.request.user.save()
        return HttpResponseRedirect(reverse('home'))

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()

        if self.request.method == 'GET':
            enable_2fa = self.request.user.two_factor_enabled
            kwargs['data'] = {
                'enable_2fa': enable_2fa
            }

        return kwargs


