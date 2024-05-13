from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from rest_framework import serializers
from .utils import get_default_role
from django.conf import settings
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "first_name", "last_name", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only letters.")
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only letters.")
        return value

    password_validator = RegexValidator(
        regex=r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_])[a-zA-Z0-9\W_]{8,}$",
        message="Password must contain at least one digit, one uppercase letter, "
        "one lowercase letter, one special character, and be at least 8 characters long.",
    )

    def validate_password(self, value):
        self.password_validator(value)
        return value

    def create(self, validated_data):
        default_role = get_default_role()
        if default_role is None:
            raise serializers.ValidationError(
                "Sorry, we are unable to process your registration request at this time. Please try again later."
            )
        validated_data["role"] = default_role
        password = validated_data.pop("password")
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user


class FileUploadSerializer(serializers.Serializer):
    files = serializers.ListField(child=serializers.FileField(), max_length=5)

    def validate_files(self, value):
        total_size = sum(file.size for file in value)
        max_size = settings.MAX_FILE_UPLOAD_SIZE

        if total_size > max_size:
            raise serializers.ValidationError(
                f"Total file size exceeds {max_size} bytes"
            )

        allowed_formats = settings.ALLOWED_FILE_UPLOAD_FORMATS

        for file in value:
            ext = file.name.lower().split(".")[-1]
            if not ext in allowed_formats:
                raise ValidationError(f"File format {file.name} not supported")

        return value
