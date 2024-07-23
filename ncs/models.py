from django.db import models
import uuid
class User(models.Model):
    userid = models.CharField(primary_key=True,max_length=100, unique=True)
    username = models.CharField(max_length=150)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username

class Friends(models.Model):
    from_user = models.ForeignKey(User, related_name='from_user_set', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='to_user_set', on_delete=models.CASCADE)

    # 무결성 보장
    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f"{self.from_user.username} -> {self.to_user.username}"
    
    
# 채팅방 모델
class ChatRoom(models.Model):
    chatroomid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    room_owner = models.CharField(max_length=255,default=uuid.uuid4)
    name = models.CharField(max_length=255)
    members = models.ManyToManyField('User', through='ChatRoomMember')

    def __str__(self):
        return self.name

# 채팅방 멤버 모델
class ChatRoomMember(models.Model):
    chat_room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('chat_room', 'user')

    def __str__(self):
        return f"{self.user.username} in {self.chat_room.name}"
    
    
# 채팅 로그
class ChatLog(models.Model):
    chatroom_id = models.CharField(max_length=255)
    sender_id = models.CharField(max_length=255)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

# AES 키 일시 저장
class TmpAESKey(models.Model):
    chatroom = models.CharField(max_length=255)
    user = models.CharField(max_length=255)
    aes_key = models.CharField(max_length=255)

    def __str__(self):
        return f"AES Key for {self.chatroom.name} by {self.user.username}"