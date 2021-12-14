
from django.urls import path, include, re_path

from .views import ValidatePhoneSendOTP
app_name = 'accounts'


urlpatterns = [
    re_path(r'^validate_phone/', ValidatePhoneSendOTP.as_view()),
]

