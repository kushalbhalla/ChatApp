from django.contrib.auth import get_user_model, logout
from rest_framework import generics
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import JSONParser

from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_201_CREATED
)

from django.core.files.storage import default_storage
from .serializers import UserSerializer, AuthTokenSerializer, ChangePasswordSerializer, CustomSerializer, CustomSerializerA, MessageSerializer, MessageSerializerA
from .authentication import token_expire_handler, expires_in
from .models import Customer, Message

from django.http import JsonResponse


class RegisterAPI(generics.GenericAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": Token.objects.create(user=user).key
            }, status=HTTP_200_OK)
        else:
            data = serializer.errors
        return Response(data)


class LoginAPI(generics.GenericAPIView):
    """Login a user and generating token"""

    permission_classes = (AllowAny,)
    serializer_class = AuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if not user:
            return Response({'error': 'Invalid Credentials'},
                            status=HTTP_404_NOT_FOUND)
        token, _ = Token.objects.get_or_create(user=user)
        is_expired, token = token_expire_handler(token)

        return Response({
        "user": UserSerializer(user, context=self.get_serializer_context()).data,
        'expires_in': expires_in(token),
        "token": token.key
        }, status=HTTP_200_OK)


from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist

class LogoutAPI(APIView):
    """Logout a user and deleting its generated token"""

    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        if not user:
            print(user)
            return Response({'error': 'Invalid Credentials'},
                            status=HTTP_404_NOT_FOUND)
        try:
            Token.objects.get(user=user).delete()
        except (AttributeError, ObjectDoesNotExist):
            return Response(data={'Not found': 'User is already logout'}, status=HTTP_404_NOT_FOUND)

        # logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=HTTP_200_OK)

class LogoutAllAPI(APIView):
    """Logout all user and all tokens"""

    permission_classes = (IsAuthenticated,)
    model = get_user_model()

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        if self.object.is_superuser:
            try:
                Token.objects.all().delete()
            except (AttributeError, ObjectDoesNotExist):
                pass
            logout(request)
            data = {'success': 'Sucessfully logged out all user'}
            return Response(data=data, status=HTTP_200_OK)
        else:
            data = {'Auth Error': 'You are not authenticated as super user'}
            return Response(data=data, status=HTTP_200_OK)


class ChangePasswordView(generics.UpdateAPIView):
    """Updating user password"""

    serializer_class = ChangePasswordSerializer
    model = get_user_model()
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["wrong password"]}, status=HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def userdetails(request):
    """Getting a user details"""

    if request.method == 'GET':
        user = request.user
        user_serializer = UserSerializer(user)
        return JsonResponse(user_serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def allusers(request):
    """Gettin gall user details by superuser"""

    if request.user.is_superuser:
        if request.method == 'GET':
            users = get_user_model().objects.filter(~Q(pk=request.user.pk)).order_by('name')
            user_serializer = UserSerializer(users, many=True)
            details = Customer.objects.filter(~Q(user=request.user.pk))
            details_serializer = CustomSerializerA(details, many=True)
            return JsonResponse({'user_serializer':user_serializer.data, 'details_serializer': details_serializer.data})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getuserdetails(request):
    """Getting customer details of logged user"""

    try:
        details = Customer.objects.get(user=request.user)
    except Customer.DoesNotExist:
        return JsonResponse({'message': 'Customer does not exists for this user'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        details_serializer = CustomSerializer(details)
        return JsonResponse(details_serializer.data, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def adduserdetails(request):
    """Adding customer details of logged user"""

    if request.method == 'POST':
        details_data = JSONParser().parse(request)
        detail_serializer = CustomSerializer(data=details_data)
        if detail_serializer.is_valid():
            detail = Customer()
            detail.user = request.user
            detail.nickname = detail_serializer.data['nickname']
            detail.phone = detail_serializer.data['phone']
            detail.language = detail_serializer.data['language']
            detail.dob = detail_serializer.data['dob']
            detail.pic = detail_serializer.data['pic']
            detail.save()
            return JsonResponse(detail_serializer.data, status=HTTP_201_CREATED)
        return JsonResponse(detail_serializer.errors, status=HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def edituserdetails(request):
    """Editting customer details of logged user"""

    if request.method == 'PUT':
        detail_data = JSONParser().parse(request)
        details = Customer.objects.get(user=request.user)
        detail_serializer = CustomSerializer(details, data=detail_data)
        if detail_serializer.is_valid():
            detail_serializer.save()
            return JsonResponse(detail_serializer.data, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def savefile(request):
    """Saving a file to the system"""

    if request.method == 'post':
        file = request.FILES['uploadedFile']
        file_name = default_storage.save(file.name, file)
        return JsonResponse(file_name, safe=False)

from django.db.models import Q

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search(request, text):
    """Searching a customer by a entred text"""

    if Customer.objects.filter(Q(nickname__contains=text)).exists():
        details = Customer.objects.filter(Q(nickname__contains=text))
        details_serializer = CustomSerializerA(details, many=True)
        users = []
        for detail in details:
            users += get_user_model().objects.filter(Q(email=detail.user.email))
            user_serializer = UserSerializer(users, many=True)
        return JsonResponse({'details_serializer': details_serializer.data, 'user_serializer': user_serializer.data})
    else:
        return JsonResponse({'message': 'search fail'}, status=HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getforeignuser(request, name):
    """Searching a customer by user name"""

    users = get_user_model().objects.get(name=name)
    users_serializer = UserSerializer(users)
    details = Customer.objects.get(user=users)
    details_serializer = CustomSerializerA(details)
    return JsonResponse({'user_serializer': users_serializer.data, 'details_serializer': details_serializer.data})

from datetime import datetime

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sendmessage(request):
    """Seanding a message """

    data = JSONParser().parse(request)
    sender = get_user_model().objects.get(name=data['sender'])
    receiver = get_user_model().objects.get(name=data['receiver'])
    data['sender']=sender.pk
    data['receiver']=receiver.pk
    print(data)
    data_serializer = MessageSerializer(data=data)
    if data_serializer.is_valid():
        sender = get_user_model().objects.get(pk=data_serializer.data['sender'])
        receiver = get_user_model().objects.get(pk=data_serializer.data['receiver'])
        date = datetime.now()
        msg = Message()
        msg.sender = sender
        msg.receiver = receiver
        print(sender)
        msg.msg = data_serializer.data['msg']
        msg.date = date
        msg.save()
        msg_serializer = MessageSerializer(msg)
        return Response(msg_serializer.data)
    else:
        return JsonResponse({'message': 'fail'}, status=HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def view_message(request, sender, receiver):
    """Gettings all message details between sender and receiver"""

    sender = get_user_model().objects.get(name=sender)
    receiver = get_user_model().objects.get(name=receiver)
    if Message.objects.filter(Q(sender=sender, receiver=receiver) | Q(sender=receiver, receiver=sender)).exists():
        msg = Message.objects.filter(Q(sender=sender, receiver=receiver) | Q(sender=receiver, receiver=sender)).order_by('date')
        msg_serializer = MessageSerializerA(msg, many=True)
        return Response(msg_serializer.data)
    else:
        return JsonResponse({'message': 'fail'}, status=HTTP_400_BAD_REQUEST)
