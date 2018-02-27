from django.urls import path, include

from mozilla_django_oidc import views


secondary_patters = [
    path('authenticate/', views.OIDCAuthenticationRequestView.as_view(), name='login'),
    path('logout/', views.OIDCLogoutView.as_view(), name='logout'),
]

urlpatterns = [
    path('callback/', views.OIDCAuthenticationCallbackView.as_view(), name='oidc_authentication_callback'),
    path('authenticate/', views.OIDCAuthenticationRequestView.as_view(), name='oidc_authentication_init'),
    path('logout/', views.OIDCLogoutView.as_view(), name='oidc_logout'),
    path('', include((secondary_patters, 'ssodotte')))
]
