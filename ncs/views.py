from django.http import JsonResponse
from django.db.models import Q
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from django.shortcuts import render,HttpResponse,redirect
from django.contrib import messages
from .models import User,Friends, ChatRoom, ChatRoomMember, ChatLog, TmpAESKey
import bcrypt, jwt ,datetime, json
import config
import os
from cryptography.hazmat.backends import default_backend
secret_key = config.settings.SECRET_KEY

def index(request):
    is_authenticated = request.is_jwt_authenticated
    userid = request.payload['id']
    print(userid)
    return render(request, 'index.html',{'is_authenticated': is_authenticated, 'user':userid})


def signup(request):
    if request.method == 'POST':
        userid = request.POST.get('userid')
        username = request.POST.get('username')
        password = request.POST.get('password')
        new_salt = bcrypt.gensalt()
        encode_password = password.encode('utf-8') 
        hashed_password = bcrypt.hashpw(encode_password, new_salt)
        decode_hash_pw = hashed_password.decode('utf-8')
        user = User(userid=userid, username=username, password=decode_hash_pw)
        user.save()
        return redirect('/')
    elif request.method == 'GET':
        return render(request, 'signup.html')
    else:
        return HttpResponse(status=400)
    
def logout(request):
    if request.method == 'GET':
        response = HttpResponse('''
            <script type="text/javascript">
                alert("로그아웃 완료");
                document.cookie.split(";").forEach(function(c) {
                    document.cookie = c.trim().split("=")[0] + '=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/';
                });
                window.location.href = "/";
            </script>
        ''')
        
        # 쿠키 삭제를 위한 설정 (보안 강화를 위해)
        response.delete_cookie('access_token')
        return response
    else:
        return HttpResponse(status=400)
    
def login(request):
    if request.method == 'POST':
        userid = request.POST.get('userid')
        password = request.POST.get('password')
        try:
            user = User.objects.get(userid=userid)
            encode_password1 = password.encode('utf-8')
            encode_password2 = user.password.encode('utf-8')
            if bcrypt.checkpw(encode_password1, encode_password2):
                expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
                payload = {
                    'id': user.userid,
                    'exp': expiration_time
                }
                token = jwt.encode(payload, secret_key, algorithm='HS256')
                response = redirect('/')
                response.set_cookie(key='access_token', value=token, httponly=True)
                return response
            else:
                messages.error(request, '로그인에 실패했습니다!')
                return render(request, 'login.html')
        except User.DoesNotExist:
            messages.error(request, '로그인에 실패했습니다!')
            return render(request, 'login.html')
    elif request.method == 'GET':
        return render(request, 'login.html')
    else:
        return HttpResponse(status=400)
    
    
    
    
    
def friends_delete(request):
    if request.method == 'POST':
        try:
            freinds_id = request.POST.get('friend_id')
            Friends.objects.filter(to_user_id=freinds_id).delete()
            Friends.objects.filter(from_user_id=freinds_id).delete()
            return HttpResponse('<script>alert("Successfully deleted"); location.href="/friends/list";</script>',status=200)
        except:
            return HttpResponse(status=400)
        
    
    
def friends_list(request):
    if request.method == 'GET':
        # 반대도 추가하기
        userid = request.payload['id']
        friends_relations = Friends.objects.filter(from_user_id=userid)
        friends = [relation.to_user for relation in friends_relations]
        friends_relations = Friends.objects.filter(to_user_id=userid)
        friends += [relation.from_user for relation in friends_relations]
        return render(request, 'friends_list.html', {'friends': friends})
    else:
        return HttpResponse(status=400)

def friends_search(request):
    if request.method == 'POST':
        userid = request.POST.get('userid')
        try:
            user = User.objects.get(userid=userid)
        except:
            user = None
        return render(request, 'friends_search.html', {'user': user})
        
    else:
        return render(request, 'friends_search.html')

def friends_add(request):
    if request.method == 'POST':
        to_id = request.POST.get('userid')
        from_id = request.payload['id']
        if to_id.lower() == from_id.lower() or to_id == '':
            return HttpResponse(status=409)
        from_user_instance = User.objects.get(userid=from_id)
        to_user_instance = User.objects.get(userid=to_id)
        
        if not Friends.objects.filter(from_user=from_user_instance, to_user=to_user_instance).exists():
            friends_relation = Friends(from_user=from_user_instance, to_user=to_user_instance)
            friends_relation.save()
            return HttpResponse(status=201)  # Created
        else:
            return HttpResponse(status=409)  # Conflict
    else:
        return HttpResponse(status=400)  # Bad Request





def generate_aes_key():
    key = os.urandom(32) # 256 bits
    return key.hex()

def chat_create(request):
    if request.method == 'GET':
        userid = request.payload['id']
        friends_relations = Friends.objects.filter(Q(from_user_id=userid) | Q(to_user_id=userid))
        friends = []
        for relation in friends_relations:
            if relation.from_user_id == userid:
                friends.append(relation.to_user)
            elif relation.to_user_id == userid:
                friends.append(relation.from_user)
        return render(request, 'make_chat.html', {'friends': friends})
    elif request.method == 'POST':
        try:
            userid = request.payload['id']
            friends_json = json.loads(request.body) 
            friends_list = friends_json.get('friends')
            room_name = friends_json.get('name')
            chat_room = ChatRoom.objects.create(name=room_name,room_owner=userid)
            aes_key = generate_aes_key()
            for friend_id in friends_list:
                user = User.objects.get(userid=friend_id)
                ChatRoomMember.objects.create(chat_room=chat_room, user=user)
                aes_key_model = TmpAESKey.objects.create(aes_key=aes_key,chatroom=chat_room.chatroomid,user=friend_id)
            user = User.objects.get(userid=userid)
            ChatRoomMember.objects.create(chat_room=chat_room, user=user)
            response_data = {
                'chatroom_id': chat_room.chatroomid,
                'aes_key': aes_key
            }
            return JsonResponse(response_data)
        except Exception as e:
            print(e)
            return HttpResponse(status=500, content=f'Error: {str(e)}')
    else:
        return HttpResponse(status=400)


def chat_list(request):
    if request.method == 'GET':
        userid = request.payload['id']
        try:
            # 해당 사용자가 속한 채팅방 멤버십 찾기
            chat_room_members = ChatRoomMember.objects.filter(user_id=userid)
            # 채팅방 ID 목록 추출
            chat_room_ids = chat_room_members.values_list('chat_room_id', flat=True)
            chat_rooms = []
            for uuid in chat_room_ids:
                print(uuid)
                rooms = ChatRoom.objects.filter(chatroomid=uuid)
                chat_rooms.extend(rooms)
            return render(request, 'chat_list.html', {'chatrooms': chat_rooms})
        except Exception as e:
            print(e)
            return render(request, 'chat_list.html')
        
def return_aes_key(request):
    userid = request.payload['id']
    AES_keys = TmpAESKey.objects.filter(user=userid).values('chatroom', 'aes_key')
    return JsonResponse({'aes_keys': list(AES_keys)})

def decrypt_message(encrypted_data, key, iv):
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes(iv)
    
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    cipher_text = encrypted_data_bytes[:-16]
    auth_tag = encrypted_data_bytes[-16:]

    # 복호화 설정
    cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv_bytes, auth_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(cipher_text) + decryptor.finalize()
    
    return decrypted.decode('utf-8')

def chat_load(request, chatid):
    userid = request.payload['id']
    chatid = chatid.replace('-', '_')
    logs = ChatLog.objects.filter(chatroom_id=chatid).order_by('-timestamp')[:20][::-1]
    decrypted_logs = []
    aes_key = request.GET.get('aes_key')
    for log in logs:
        data = json.loads(log.message)
        print(data)
        decrypted_message = decrypt_message(data['message'], aes_key, data['iv'])
        decrypted_logs.append({
            'sender_id': log.sender_id,
            'message': decrypted_message,
            'timestamp': log.timestamp
        })
    chatid = chatid.replace('_', '-')
    try:
        TmpAESKey.objects.filter(chatroom=chatid,user=userid).delete()
    except:
        pass
    return render(request, 'chat_room.html', {'chat_logs': decrypted_logs})