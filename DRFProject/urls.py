from django.conf.urls.static import static
from django.conf import settings
from django.urls import path
from DrfAPI.views import (
    UserRegistrationView,
    SpecificProductView,
    PurchaseHistoryView,
    MyProtectedView,
    UserLogoutView,
    UserLoginView,
    PurchaseView,
    ProductView,
)

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("reg/", MyProtectedView.as_view(), name="user-reg"),
    path("products/buy/", PurchaseView.as_view(), name="product-sale"),
    path("products/create/", ProductView.as_view(), name="product-create"),
    path("products/show/", ProductView.as_view(), name="products-detail"),
    path("PurchaseHistory/", PurchaseHistoryView.as_view(), name="PurchaseHistory"),
    path(
        "products/update/<int:pk>/",
        SpecificProductView.as_view(),
        name="product-update",
    ),
    path(
        "products/delete/<int:pk>/",
        SpecificProductView.as_view(),
        name="product-delete",
    ),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
