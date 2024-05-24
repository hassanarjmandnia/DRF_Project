from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):

    first_name = models.CharField(
        max_length=30,
        blank=False,
    )

    last_name = models.CharField(
        max_length=30,
        blank=False,
    )

    email = models.EmailField(
        unique=True,
        blank=False,
    )

    role = models.ForeignKey(
        "Role",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)


class Product(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, null=False, blank=False
    )
    title = models.CharField(max_length=255, blank=False)
    description = models.TextField(max_length=500)
    price = models.DecimalField(
        max_digits=10, decimal_places=2, null=False, blank=False
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class ProductFile(models.Model):
    product = models.ForeignKey(
        "Product", related_name="files", on_delete=models.CASCADE
    )
    file = models.FileField(upload_to="product_files/")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"File {self.id} for Product: {self.product.title}"


class Sale(models.Model):
    buyer = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, null=False, blank=False
    )
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, null=False, blank=False
    )
    created_at = models.DateTimeField(auto_now_add=True)
