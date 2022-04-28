from django.urls import path

from .views import LoginView, TwoFactorView, OTPView, TOTPView, LoginSuccessView, home, SignUpView, LogoutView, UserSettingsView

urlpatterns = [

    path('', home, name='home'),

    path('login/', LoginView.as_view(), name='login'),
    path('register/', SignUpView.as_view(), name='register',),
    path('logout/', LogoutView.as_view(), name='logout',),

    path('two-factor/', TwoFactorView.as_view(), name='two-factor'),
    path('otp/', OTPView.as_view(), name='otp'),
    path('authenticator/', TOTPView.as_view(), name='totp'),
    path('login-success/', LoginSuccessView.as_view(), name='login-success'),

    path('user-settings/', UserSettingsView.as_view(), name='user-settings'),
]