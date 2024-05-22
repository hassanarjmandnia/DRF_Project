from DrfAPI.views import (
    UserRegistrationView,
    MyProtectedView,
    UserLogoutView,
    UserLoginView,
    ProductView,
)
from django.urls import path

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("reg/", MyProtectedView.as_view(), name="user-reg"),
    path("products/create/", ProductView.as_view(), name="product-create"),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
