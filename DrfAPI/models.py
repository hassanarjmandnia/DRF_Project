from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
import os


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
    quantity = models.IntegerField(null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class ProductFile(models.Model):
    product = models.ForeignKey(
        "Product", related_name="files", on_delete=models.CASCADE
    )
    file = models.FileField(upload_to="product_files/")
    original_name = models.CharField(
        max_length=255,
    )
    file_format = models.CharField(max_length=50)
    file_size = models.PositiveIntegerField()
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"File {self.id} for Product: {self.product.title}"

    def save(self, *args, **kwargs):
        if not self.pk:
            self.original_name = self.file.name
            self.file_format = os.path.splitext(self.file.name)[1][1:].lower()
            self.file_size = self.file.size

            created_at_str = (
                self.uploaded_at.strftime("%Y%m%d%H%M%S") if self.uploaded_at else ""
            )
            random_str = uuid.uuid4().hex[:8]
            user_id = self.product.user_id
            name_without_extension = os.path.splitext(self.file.name)[0]
            new_file_name = f"{name_without_extension}_{created_at_str}_{random_str}_{user_id}.{self.file_format}"
            self.file.name = new_file_name

        super().save(*args, **kwargs)


class Sale(models.Model):

    buyer = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, null=False, blank=False
    )
    total_price = models.DecimalField(
        max_digits=10, decimal_places=2, null=False, blank=False, default=50
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # def save(self, *args, **kwargs):
    #    total_price = sum(
    #        product.price * product.saleproduct.quantity
    #        for product in self.products.all()
    #    )
    #    self.total_price = total_price
    #    super(Sale, self).save(*args, **kwargs)


class SaleProduct(models.Model):
    sale = models.ForeignKey(Sale, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    price = models.DecimalField(
        max_digits=10, decimal_places=2, null=False, blank=False
    )
