from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    
    def set_default_role():
        try:
            default_role = Role.objects.get(name="User")
            return default_role.id
        except Role.DoesNotExist:
            raise Role.DoesNotExist(
                "Sorry, we are unable to process your registration request at this time. Please try again later."
            )

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
        on_delete=models.SET_DEFAULT,
        default=set_default_role,
    )


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
