from datetime import timedelta
from lib2to3.fixes.fix_input import context


from fastapi import FastAPI, Depends, HTTPException, Request, Form, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles


from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates
from security import ACCESS_TOKEN_EXPIRE_MINUTES, COOKIE_NAME,  hash_password, oauth2_scheme
from featureExtractor import featureExtraction as get_feature

from sqlalchemy.orm import Session

# import database and the model
import models
from database import get_db, engine
from util import UserRepository, authenticate_user, get_current_user


models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")

app = FastAPI()
app.mount("/static", StaticFiles(directory='static', html=True), name='static')


def get_cookies(request):
    return request.cookies.get(COOKIE_NAME)


@app.get("/")
async def home(request: Request, db: Session = Depends(get_db)):
    cookie_token = get_cookies(request)
    if not cookie_token:
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    current_user = await get_current_user(db, cookie_token)
    return templates.TemplateResponse("index.html", {"request": request, "current_user": current_user})


@app.get("/login")
def login(request: Request):
    cookie_token = get_cookies(request)
    if cookie_token:
        url = app.url_path_for("home")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("/login.html", {"request": request, "current_user": False})


@app.get("/register")
def register(request: Request, db: Session = Depends(get_db)):
    cookie_token = get_cookies(request)
    if cookie_token:
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {"request": request, "current_user": False})


@app.post("/registeruser")
async def register_user(request: Request, email: str = Form(), username: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    userSession = UserRepository(db)
    is_username_exist = userSession.get_user_by_username(username)
    is_email_exist = userSession.get_user_by_email(email)

    if is_username_exist or is_email_exist:
        return {"message": "username or email already exist"}

    signup_data = models.User(
        email=email, username=username, password=hash_password(password))
    success = userSession.create_user(signup_data)
    if success:
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    else:
        url = app.url_path_for("register")
        return RedirectResponse(url=url, status_code=status.HTTP_404_NOT_FOUND)


@app.post("/loginuser")
async def user_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    error = "welcome"
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = UserRepository.create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
   
    url = app.url_path_for("home")
    resp = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        httponly=True,
        expires=access_token_expires
    )
    return resp


@app.get("/logout")
def logout(resp: Response, request: Request):
    url = app.url_path_for("login")
    cookie_token = get_cookies(request)
    if cookie_token:
        resp = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
        resp.delete_cookie(key=COOKIE_NAME)
        return resp


@app.get("/detect/")
def detect_url(url: str, db: Session = Depends(get_db)):
    features = get_feature(url)
    return  features
