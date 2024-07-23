# consumers.py
from django.utils import timezone
import jwt
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from .models import ChatLog
import json
from channels.db import database_sync_to_async

class MyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # UUID 객체를 문자열로 변환하고, 하이픈을 밑줄로 변경
        self.room_group_name = str(self.scope['url_route']['kwargs']['chatroom_id']).replace('-', '_')
        print(self.room_group_name)
        print(self.channel_name)
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        print("Connection established")
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
        print("Connection closed")

    async def receive(self, text_data):
        token = self.scope['cookies'].get('access_token')
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload['id']  # 토큰에서 사용자 ID 추출
            except jwt.ExpiredSignatureError:
                user_id = 'Expired Token'
            except jwt.InvalidTokenError:
                user_id = 'Invalid Token'
        else:
            user_id = 'Anonymous'

        chatroom_id = self.room_group_name  # URL에서 채팅방 ID 추출
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        print(timestamp)
        # 채팅 로그 저장 (비동기적 실행)
        await self.save_chat_log(chatroom_id, user_id, text_data)
        
        # 그룹 내 모든 사용자에게 메시지 전송
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat.message',
                'message': text_data,
                'user_id': user_id,
                'timestamp': timestamp
            }
        )

    @database_sync_to_async
    def save_chat_log(self, chatroom_id, sender_id, message):
        ChatLog.objects.create(
            chatroom_id=chatroom_id,
            sender_id=sender_id,
            message=message
        )

    # 채팅 메시지 처리
    async def chat_message(self, event):
        message = event['message']
        user_id = event['user_id']
        timestamp = event['timestamp']
        # 클라이언트로 메시지와 사용자 ID 전송
        await self.send(text_data=json.dumps({'message': message, 'user_id': user_id, 'timestamp':timestamp}))
