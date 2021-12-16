from django.shortcuts import render
from rest_framework import generics, status, views, permissions
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from .serializers import RegisterSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer, LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, EmailVerificationSerializer
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
from rest_framework.generics import GenericAPIView
import os
import random
import string


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


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
    serializer_class = EmailVerificationSerializer
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


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)



class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
