from DrfAPI.views import (
    UserRegistrationView,
    UserLoginView,
    MyProtectedView,
    UserLogoutView,
)
from django.urls import path


urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("reg/", MyProtectedView.as_view(), name="user-reg"),
]
