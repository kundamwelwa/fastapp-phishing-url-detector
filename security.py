from typing import Annotated, Union
from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel
from models import User
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer




JWT_SECRET = "ph1sh1n83442De73c7i0n"
ALGORITHM ="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="loginuser")
COOKIE_NAME = "Authorization"

class Token(BaseModel):
    access_token: str
    token_type: str



#Create Token
def create_access_token(user:User):
    try:
        payload ={
            "username":user.username,
            "email": user.email,
            "role": user.role.value,
            "active": user.isActive,
        }
        return jwt.encode(payload, key=JWT_SECRET, algorithm=ALGORITHM)
    except Exception as e:
        print(str(e))
        raise e


#password security
def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

   
def hash_password(password) -> str:
    return pwd_context.hash(password)
    

