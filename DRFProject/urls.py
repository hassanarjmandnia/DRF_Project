from django.conf.urls.static import static
from django.conf import settings
from django.urls import path
from DrfAPI.views import (
    UserRegistrationView,
    SpecificProductView,
    MyProtectedView,
    UserLogoutView,
    UserLoginView,
    ProductView,
)

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("reg/", MyProtectedView.as_view(), name="user-reg"),
    path("products/create/", ProductView.as_view(), name="product-create"),
    path(
        "products/delete/<int:pk>/",
        SpecificProductView.as_view(),
        name="product-delete",
    ),
    path("products/show/", ProductView.as_view(), name="products-detail"),
    path(
        "products/show/<int:pk>/", SpecificProductView.as_view(), name="product-detail"
    ),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
