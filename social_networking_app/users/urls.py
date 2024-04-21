from django.urls import path,include
from users.views import *
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('create_user/',CreateUser.as_view()),
    path('login_user/',Login.as_view()),
    path('userlisting/',UserListing.as_view()),
]
