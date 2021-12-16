from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, EmailVerification
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from .serializers import LoginSerializer
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from rest_framework.generics import GenericAPIView
import random
import string
def generate_otp(num):
    return ''.join(random.choice(string.digits) for i in range(num))
class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        OTP = generate_otp(6)
        user.otp = OTP
        user.save()
        current_site = get_current_site(request).domain
        absurl = 'http://'+current_site+'?token='+str(OTP)
        email_body = 'Hi ' + user.username + ' use the link to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email':user.email,'email_subject':'verify your email'}
        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)
class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerification
    def post(self, request):
        data = request.data
        otp = data.get('otp', '')
        email = data.get('email', '')
        if otp is None or email is None:
            return Response(errors=dict(invalid_input="Please provide both otp and email"), status=status.HTTP_400_BAD_REQUEST)
        get_user = User.objects.filter(email=email)
        if not get_user.exists():
            return Response(errors=dict(invalid_email="please provide a valid registered email"), status=status.HTTP_400_BAD_REQUEST )
        user = get_user[0]
        if user.otp != otp:
            return Response(errors=dict(invalid_otp="please provide a valid otp code"), status=status.HTTP_400_BAD_REQUEST)
        user.is_verified = True
        user.save()
        return Response(data={
                "verified status":"Your account has been successfully verified"
            }, status=status.HTTP_200_OK)
class LoginView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        if email is None or password is None:
            return Response(errors={'invalid_credentials': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=email, password=password)
        if not user:
            return Response(errors={'invalid_credentials': 'Ensure both email and password are correct and you have verify you account'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response(errors={'invalid_credentials': 'Please verify your account'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(user)
        token, _ = Token.objects.get_or_create(user=user)
        return Response(data={'token': token.key}, status=status.HTTP_200_OK)