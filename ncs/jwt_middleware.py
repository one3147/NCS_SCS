import jwt
from django.http import JsonResponse, HttpResponse
from django.utils.deprecation import MiddlewareMixin
import config
secret_key = config.settings.SECRET_KEY
from django.shortcuts import render, redirect
class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.is_jwt_authenticated = False
        
        # 토큰이 필요 없는 경로는 JWT 인증에서 제외
        if request.path_info in ['/login', '/signup']:
            return None
        
        # 채팅방 버튼 / 로그인 버튼 중 하나를 보여주기 위해 토큰 파싱
        if request.path_info in '/':
            token = request.COOKIES.get('access_token')
            if token == '':
                return None
            else:
                try:
                    payload = jwt.decode(token, secret_key, algorithms=['HS256'])
                    is_authenticated = True
                except jwt.ExpiredSignatureError:
                    is_authenticated = False
                    response = render(request,'index.html')
                    return response
                except jwt.InvalidTokenError:
                    is_authenticated = False
                    response = render(request,'index.html')
                    return response
                request.is_jwt_authenticated = is_authenticated
                request.payload = payload
                return None
        token = request.COOKIES.get('access_token')
        
        # 토큰 없으면 /login Redirection
        if not token:
            return redirect('/login')
        
        # 토큰 파싱, 성공 시 next(), 실패 시 /login Redirection
        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            is_authenticated = True
        except jwt.ExpiredSignatureError:
            is_authenticated = False
            response = render(request,'login.html')
            return response
        except jwt.InvalidTokenError:
            is_authenticated = False
            response = render(request,'login.html')
            return response
        request.is_jwt_authenticated = is_authenticated
        request.payload = payload
        print(payload)
        return None
