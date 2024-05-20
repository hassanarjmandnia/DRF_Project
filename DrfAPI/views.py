from .serializers import UserSerializer, ProductSerializer, ProductFileSerializer
from django.contrib.auth import login, authenticate, logout
from django.core.files.storage import FileSystemStorage
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.conf import settings
import logging

info_logger = logging.getLogger("info_logger")


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            info_logger.info(f"User '{user.username}' registered successfully.")
            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            info_logger.info(f"User '{user.username}' logged_in successfully.")
            return Response(
                {"message": "Login successful"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        username = request.user.username
        info_logger.info(f"User '{username}' logged out successfully.")
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


class MyProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": f"Hello, {request.user.username}!"})


class ProductCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        files_data = [{"file": file} for file in request.FILES.getlist("files")]
        product_serializer = ProductSerializer(
            data=request.data, context={"request": request}
        )
        product_file_serializer = ProductFileSerializer(data=files_data, many=True)
        if product_serializer.is_valid():
            if product_file_serializer.is_valid():
                product = product_serializer.save(user=request.user)
                product_file_serializer.save(product=product)
                return Response(product_serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(
                    product_file_serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                product_serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
