import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

django_asgi_app = get_asgi_application()

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import ncs.routing

application = ProtocolTypeRouter({
    "http": django_asgi_app,  # Django의 기본 ASGI 애플리케이션을 HTTP 프로토콜 타입으로 설정
    "websocket": AuthMiddlewareStack(
        URLRouter(
            ncs.routing.websocket_urlpatterns
        )
    ),
})
