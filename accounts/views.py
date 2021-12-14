from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response

from .models import User, PhoneOTP
from django.shortcuts import get_object_or_404
import random


class ValidatePhoneSendOTP(APIView):


    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact = phone)
            if user.exists():
                return Response({
                    'status' : False,
                    'detail' : 'phone number already exist'
                })
            else:
                key = send_otp(phone)
                if key:
                    old = PhoneOTP.objects.filter(phone_iexact = phone)
                    if old.exists():
                        old = old.first()
                        count = old.count
                        if count > 5: 
                            return Response({
                                    'status' : False,
                                    'detail' : 'Sending otp error. Limit exceeded. Please contact customer support'
                            })

                        old.count = count + 1 
                        old.save()
                        return Response({
                            'status' : True,
                            'detail' : 'OTP sent successfully'
                        })

                    else:


                        PhoneOTP.objects.create(
                            phone = phone, 
                            otp = key,             
                            
                        )
                        return Response({
                            'status' : True,
                            'detail' : 'OTP sent successfully'
                        })

                else:
                    return Response({
                        'status' : False,
                        'detail' : 'Sending otp error'
                    })


        else:
            return Response({
                'status' : False,
                'detail' : 'Phone number is not given in post request'
            })




def send_otp(phone):
    if phone:
        key = random.randint(999, 9999)
    else:
        return False