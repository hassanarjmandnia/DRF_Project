import logging
from django.http import HttpResponse
from rest_framework.views import APIView

logger = logging.getLogger("DrfAPI")


class MyAPIView(APIView):
    def get(self, request):
        logger.debug("This is a debug message")
        logger.info("This is an info message")
        logger.warning("This is a warning message")
        logger.error("This is an error message")
        logger.critical("This is a critical message")
        return HttpResponse("Hello, world!")
