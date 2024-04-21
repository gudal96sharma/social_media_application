from .models import *
from rest_framework import serializers
import string,random
from .models import *
import bcrypt 

def encrypt(password):
    encrypted_password = ""
    key=42
    for char in password:
        encrypted_password += chr((ord(char) + key) % 256)
    return encrypted_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name','phone','email','password')
        
    def create(self,validated_data):
        password = validated_data['password'] 
        encrypted_password = encrypt(password)
        user = User(
            name                    = validated_data['name'],
            phone                   = validated_data['phone'],
            email                       = validated_data['email'],
            password                =  encrypted_password
        )
        user.save()
        return user

class EmailLoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()


