import jwt
from django.conf import settings
from .models import *
from .serializers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q
from datetime import datetime, timedelta
from django.utils import timezone 
from botocore.exceptions import ClientError
import boto3


def validatedate(date_text):
    try:
        datetime.strptime(date_text,'%Y-%m-%d')
        return True
    except :
        return False

def decrypt(encrypted_email):
    decrypted_email = ""
    key=42
    for char in encrypted_email:
        decrypted_email += chr((ord(char) - key) % 256)
    return decrypted_email


def generate_token(name,phone,email,password):
    payload = {
        'name' : name,
        'phone':phone,
        'email' : email,
        'password': password,
        'exp': datetime.utcnow() + timedelta(hours=24),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS512')
    return token

def handle_auth_exceptions(func):
    def wrapper(*args, **kwargs):
        result = {}
        result['status'] =  'NOK'
        result['valid']  =  False
        result['result'] = {"message":"Unauthorized access","data" :{}}
        try:
            request = args[1]  # Assuming the request is the second argument
            header_access_token = request.META.get('HTTP_AUTHORIZATION')
            if not header_access_token:
                result['result']['message'] = "Authorization header missing"
                return Response(result,status=status.HTTP_400_BAD_REQUEST)
            splited_access_token = header_access_token.split(' ')
            if len(splited_access_token) != 2:
                result['result']['message'] = "Authorization header missing"
                return Response(result,status=status.HTTP_400_BAD_REQUEST)
            access_token = splited_access_token[1]
            user_data = jwt.decode(access_token, settings.JWT_SECRET_KEY, algorithms=["HS512"])
            if not user_data or 'email' not in user_data:
                result['result']['message'] = "User data not found in token"
                return Response(result,status=status.HTTP_401_UNAUTHORIZED)
            request.user_data = user_data
            return func(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            result['result']['message'] = "Token expired. Please login again"
            return Response(result, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            result['result']['message'] = "User not found"
            return Response(result, status=status.HTTP_404_NOT_FOUND)
        except ValueError as e:
            result['result']['message'] = str(e)
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            result['result']['message'] = str(e)
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return wrapper

class CreateUser(APIView):
    def post(self,request):
        result = {}
        result['status'] =  'NOK'
        result['valid']  =  False
        result['result'] = {"message":"Unauthorized access","data" :{}}

        email = request.data['email']
        phone = request.data['phone']

        if len(email)>0:
            email_data = User.objects.filter(email=email)
            if len(email_data)>0:
                result['result'] = {"message":"User with this email already exists","data" :{}}
                return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        elif len(phone)>0:
            phone_data = User.objects.filter(phone = phone)
            if len(phone_data)>0:
                result['result'] = {"message":"User with this phone number already exists","data" :{}}
                return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        serializer       = UserSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
                
            result['status']    =   "OK"
            result['valid']     =   True
            result['result']['message'] =   "User registered successfully"
            result['result']['data'] = serializer.data
            return Response(result,status=status.HTTP_200_OK)

        else:
            result['result']['message'] = (list(serializer.errors.keys())[
                0]+' - '+list(serializer.errors.values())[0][0]).capitalize()
            return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

class Login(APIView):
    def post(self,request):
        result = {}
        result['status']    =   "NOK"
        result['valid']     =   False
        result['result']    =   {"message":"Unauthorized access","data":{}}
        serializer = EmailLoginSerializer(data = request.data)
        if serializer.is_valid():
            email           = serializer.validated_data['email']
            password        = serializer.validated_data['password']
            try:
                user_data       = User.objects.get(email=email)
            except Exception as e:
                    result['result']['message'] = "Invalid Username or Password"
                    return Response(result, status=status.HTTP_401_UNAUTHORIZED)
    
            if (user_data is None):
                result['result']['message'] = "Invalid username or password"
                return Response(result, status=status.HTTP_401_UNAUTHORIZED)
            else:
                decrypted_password = decrypt(user_data.password)
                if decrypted_password != password:
                    result['result']['message'] = "Incorrect password"
                    return Response(result, status=status.HTTP_401_UNAUTHORIZED)
                token                       =   generate_token(user_data.name,user_data.phone,user_data.email,user_data.password)
                final_response  =   {
                            'name'          : user_data.name,
                            'last_login'    : (datetime.today()).strftime('%Y-%m-%d %H:%M:%S'),
                            'user_id'       : user_data.id,
                            'email'         : user_data.email,
                            'phone_number'  : user_data.phone,
                            'token'         : token,
                        }

                result['status']            =   "OK"
                result['valid']             =   True
                result['result']['message'] =   "You are successfully logged in."
                result['result']['data']    =   final_response
                return Response(result,status=status.HTTP_200_OK)
                    
        else:
            result['result']['message'] = (list(serializer.errors.keys())[
                0]+' - '+list(serializer.errors.values())[0][0]).capitalize()
            return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

class UserListing(APIView):
    def post(self,request):
        result = {}
        result['status']    =   "NOK"
        result['valid']     =   False
        result['result']    =   {"message":"Unauthorized access","data":{}}
        try:
            search = request.data.get('search')
            data = User.objects.all().values('name','email','phone')
            if search != "":
                data=data.filter(Q(name__icontains=search)|Q(email__icontains=search))
                
            result['status']            =   "OK"
            result['valid']             =   True
            result['result']['message'] =   "Data fetched successfully."
            result['result']['data']    =   data
            return Response(result,status=status.HTTP_200_OK)        
        except Exception as e:
            result['result']['message'] = str(e)
            return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)