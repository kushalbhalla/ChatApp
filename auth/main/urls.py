from django.urls import path, include

from . import views as mainViews

app_name = "main"

urlpatterns = [
    path('api/register/', mainViews.RegisterAPI.as_view(), name='register'),
    path('api/login/', mainViews.LoginAPI.as_view(), name='login'),
    path('api/logout/', mainViews.LogoutAPI.as_view(), name='logout'),
    path('api/change-password/', mainViews.ChangePasswordView.as_view(), name='change-password'),
    path('api/logoutall/', mainViews.LogoutAllAPI.as_view(), name='logoutall'),
    path('api/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('api/userdetails/', mainViews.userdetails, name='userdetails'),
    path('api/allusers/', mainViews.allusers, name='allusers'),
    path('api/getuserdetails/', mainViews.getuserdetails, name='getuserdetails'),
    path('api/adduserdetails/', mainViews.adduserdetails, name='adduserdetails'),
    path('api/edituserdetails/', mainViews.edituserdetails, name='edituserdetails'),
    path('api/savefile/', mainViews.savefile, name='savefile'),
    path('api/search/<str:text>', mainViews.search, name='search'),
    path('api/getforeignuser/<str:name>', mainViews.getforeignuser, name='getforeignuser'),
    path('api/sendmessage/', mainViews.sendmessage, name='sendmessage'),
    path('api/viewmessage/<str:sender>/<str:receiver>', mainViews.view_message, name='viewmessage'),
]
