from django.db import models
from django.contrib.auth.models import AbstractBaseUser

# Create your models here.
class User(AbstractBaseUser):
    name                       = models.CharField(max_length=25,null=False,blank=False,default=True)
    email                      = models.EmailField(max_length = 50,null=False,blank=False,unique=True)
    phone                      = models.CharField(max_length=10,null=True,blank=True)
    password                   = models.CharField(max_length=1024,null=True,blank=True)
    is_active                  = models.BooleanField(default=True)
    is_deleted                 = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    def __str__(self):
        return self.email