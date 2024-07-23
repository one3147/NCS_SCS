from django.urls import path
from .consumers import MyConsumer
websocket_urlpatterns = [
    path('ws/chat/<uuid:chatroom_id>/', MyConsumer.as_asgi()),
]