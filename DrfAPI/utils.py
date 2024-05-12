from .models import Role


def get_default_role():
    try:
        default_role = Role.objects.get(name="User")
        return default_role
    except Role.DoesNotExist:
        return None
