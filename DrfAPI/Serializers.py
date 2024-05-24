from .models import CustomUser, Product, ProductFile, Sale
from django.core.validators import RegexValidator
from rest_framework import serializers
from .utils import get_default_role
from django.conf import settings
import re


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


class ProductFileSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = ProductFile
        fields = ["id", "file", "file_url"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        if obj.file:
            return request.build_absolute_uri(obj.file.url)
        return None


class ProductCreateSerializer(serializers.ModelSerializer):

    files = serializers.ListField(
        child=serializers.FileField(), write_only=True, allow_empty=False
    )
    file_details = ProductFileSerializer(source="files", many=True, read_only=True)

    class Meta:
        model = Product
        fields = [
            "id",
            "title",
            "description",
            "price",
            "files",
            "file_details",
            "user_id",
        ]

    def validate_title(self, value):
        if not value.strip():
            raise serializers.ValidationError("Title cannot be blank.")
        if not re.match(r"^[a-zA-Z0-9\s]+$", value):
            raise serializers.ValidationError("Title must be alphanumeric.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Title must be at least 10 characters long."
            )
        return value

    def validate_description(self, value):
        if not value.strip():
            raise serializers.ValidationError("Description cannot be blank.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Description must be at least 10 characters long."
            )
        return value

    def validate_price(self, value):
        if value is None or value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value

    def validate_files(self, files):
        if not (1 <= len(files) <= 5):
            raise serializers.ValidationError(
                "Number of files must be between 1 and 5."
            )
        total_size = 0
        for file in files:
            if not any(
                file.name.endswith(ext) for ext in settings.ALLOWED_FILE_UPLOAD_FORMATS
            ):
                raise serializers.ValidationError(
                    f"Invalid file type. Allowed types are: {', '.join(settings.ALLOWED_FILE_UPLOAD_FORMATS)}"
                )
            total_size += file.size
        if total_size > settings.MAX_FILE_UPLOAD_SIZE:
            raise serializers.ValidationError(
                f"Total file size must be under {settings.MAX_FILE_UPLOAD_SIZE / (1024 * 1024)} MB"
            )
        return files

    def create(self, validated_data):
        files = validated_data.pop("files", [])
        product = Product.objects.create(**validated_data)
        return product


class ProductReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "title", "description", "price", "user_id"]


class ProductSaleSerializer(serializers.ModelSerializer):

    class Meta:
        model = Sale
        fields = ["id", "buyer", "product", "created_at"]
