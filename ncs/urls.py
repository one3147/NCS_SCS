from django.urls import path
from ncs import views
urlpatterns = [
     path('', views.index),
     path('signup',views.signup),
     path('login',views.login),
     path('logout',views.logout),
     
     path('chat/create',views.chat_create),
     path('chat/list',views.chat_list),
     path('chat/<str:chatid>',views.chat_load),
     
     path('friends/search',views.friends_search),
     path('friends/add',views.friends_add),
     path('friends/list',views.friends_list),
     path('friends/delete',views.friends_delete),
     
     path('aes_key',views.return_aes_key)
     
]
