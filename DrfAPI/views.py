from rest_framework.views import APIView
from django.http import HttpResponse
import logging

debug_logger = logging.getLogger("debug_logger")
info_logger = logging.getLogger("info_logger")
warning_logger = logging.getLogger("warning_logger")
error_logger = logging.getLogger("error_logger")
critical_logger = logging.getLogger("critical_logger")


class MyAPIView(APIView):
    def get(self, request):
        debug_logger.debug("This is a debug message")
        info_logger.info("This is an info message")
        warning_logger.warning("This is a warning message")
        error_logger.error("This is an error message")
        critical_logger.critical("This is a critical message")
        return HttpResponse("Hello, world!")
