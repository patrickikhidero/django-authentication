from django.urls import path, include, re_path
from django.contrib import admin
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="USER AUTHENTICATION API",
        default_version='v1',
        description="Verifies User, Create User Accounts",
        terms_of_service="https://www.piogatesolutions.com/",
        contact=openapi.Contact(email="info@piogatesolution.com"),
        license=openapi.License(name="Test License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [

    path(r'admin/', admin.site.urls),
    re_path(r'api/', include('accounts.urls', namespace='accounts')),
    
]
urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('accounts/', include('accounts.urls')),
    path('', schema_view.with_ui('swagger',
                                 cache_timeout=0), name='schema-swagger-ui'),

    path('api/api.json/', schema_view.without_ui(cache_timeout=0),
         name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
                                       cache_timeout=0), name='schema-redoc'),
]