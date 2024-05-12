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
