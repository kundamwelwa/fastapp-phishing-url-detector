from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Form, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse, JSONResponse
from starlette.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from urllib.parse import urlparse
from models import Report
from report_repo import ReportRepo
from aipredictor import predict_url
from security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    COOKIE_NAME,
    hash_password,
    oauth2_scheme
)
from database import get_db, engine
from util import UserRepository, authenticate_user, get_current_user
from email_utils import send_email_with_report
import models

# Initialize database and FastAPI app
models.Base.metadata.create_all(bind=engine)
templates = Jinja2Templates(directory="templates")
app = FastAPI()

# Mount static files for CSS/JS resources
app.mount("/static", StaticFiles(directory="static"), name="static")

# Helper function: Get cookies
def get_cookies(request: Request):
    return request.cookies.get(COOKIE_NAME)

# URL validation function
def is_valid_url(url: str) -> bool:
    """Validates if the given URL is correctly formatted and uses HTTP or HTTPS."""
    parsed = urlparse(url)
    return bool(parsed.scheme in ["http", "https"] and parsed.netloc)

# JSON model for URL detection
class DetectRequest(BaseModel):
    url: str

# Secure endpoint example
@app.get("/secure-endpoint")
async def secure_endpoint(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    current_user = await get_current_user(db, token)
    if not current_user:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return {"message": "You have access", "user": current_user.username}

# Home route
@app.get("/")
async def home(request: Request, db: Session = Depends(get_db)):
    cookie_token = get_cookies(request)
    if not cookie_token:
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    
    current_user = await get_current_user(db, cookie_token)
    if not current_user:
        return RedirectResponse(url=app.url_path_for("login"), status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("index.html", {"request": request, "current_user": current_user})

# Login route
@app.get("/login")
def login(request: Request):
    cookie_token = get_cookies(request)
    if cookie_token:
        url = app.url_path_for("home")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request, "current_user": False})

# Register route
@app.get("/register")
def register(request: Request):
    cookie_token = get_cookies(request)
    if cookie_token:
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {"request": request, "current_user": False})

# Register user
@app.post("/registeruser")
async def register_user(
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user_repo = UserRepository(db)
    if user_repo.get_user_by_username(username) or user_repo.get_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists"
        )

    new_user = models.User(
        email=email, username=username, password=hash_password(password)
    )
    if user_repo.create_user(new_user):
        url = app.url_path_for("login")
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error creating user"
    )

# User login
@app.post("/loginuser")
async def user_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
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

# Logout route
@app.get("/logout")
def logout(resp: Response, request: Request):
    url = app.url_path_for("login")
    cookie_token = get_cookies(request)
    if cookie_token:
        resp = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
        resp.delete_cookie(key=COOKIE_NAME)
        return resp

@app.post("/detect/")
async def detect_url(detect_request: DetectRequest):
    url = detect_request.url

    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format.")
    
    try:
        # Debugging: Print/log the incoming URL
        print(f"Processing URL: {url}")

        result = await predict_url(url)
        
        # Validate result structure
        print(f"Predict URL result: {result}")  # Debugging
        if not isinstance(result, dict):
            raise HTTPException(status_code=500, detail="Invalid response format from predict_url.")

        if "features" not in result or "is_phishing" not in result:
            raise HTTPException(status_code=500, detail="Missing required keys in predict_url response.")
        
        # Ensure feature count matches expected input for the model
        feature_count = len(result.get("features", []))
        if feature_count != 16:  # Replace 16 with your model's expected feature count
            raise ValueError(f"Feature count mismatch! Expected 16, got {feature_count}")
        
        # Interpret the prediction result
        is_phishing = result.get("is_phishing", False)
        if isinstance(is_phishing, list) and len(is_phishing) == 1:
            is_phishing = bool(is_phishing[0])

        result_message = "phishing" if is_phishing else "legitimate"

        # Get HTTPS/SSL details from the prediction result
        is_https = result.get("is_https", False)
        ssl_error = result.get("ssl_error", False)

        return JSONResponse(content={
            "success": True,
            "url": url,
            "result": result_message,
            "is_phishing": is_phishing,
            "is_https": is_https,  # Add HTTPS info
            "ssl_error": ssl_error  # Add SSL error info
        })
    
    except Exception as e:
        # Log detailed errors for debugging
        print(f"Error during URL detection: {e}")
        raise HTTPException(status_code=500, detail=f"Error during URL detection: {str(e)}")



# Generate user report
@app.post("/report/")  
async def request_report(request: Request, db: Session = Depends(get_db)):
    """
    Generate a report for the logged-in user and send it via email.

    Args:
        request (Request): The HTTP request object.
        db (Session): The database session.

    Returns:
        dict: Response indicating success or failure.
    """
    # Retrieve the user's authentication cookie
    cookie_token = get_cookies(request)
    if not cookie_token:
        return {"success": False, "message": "Unauthorized: Missing cookie token"}

    # Authenticate the current user
    current_user = await get_current_user(db, cookie_token)
    if not current_user:
        return {"success": False, "message": "User not found or unauthorized"}

    # Fetch user's reports from the database
    try:
        reports = ReportRepo(db).get_reports_by_user(current_user.id)
    except Exception as db_error:
        print(f"Database error: {db_error}")  # Logging for debugging
        raise HTTPException(status_code=500, detail="Failed to retrieve user reports.")

    # Check if reports exist
    if not reports:
        return {"success": False, "message": "No reports found for this user."}

    # Prepare report content: Separate phishing and legitimate URLs
    phishing_urls = []
    legitimate_urls = []

    for report in reports:
        url_info = {
            "url": report.site_url,
            "status": 'Phishing' if report.is_phishing == 'yes' else 'Legitimate'
        }
        if report.is_phishing == 'yes':
            phishing_urls.append(url_info)
        else:
            legitimate_urls.append(url_info)

    # Construct the report content
    report_content = (
        f"Phishing Detection Report\n\n"
        f"User: {current_user.username}\n"
        f"Email: {current_user.email}\n\n"
        f"Phishing URLs:\n" +
        ("\n".join([f"{url['url']} - {url['status']}" for url in phishing_urls]) if phishing_urls else "None") +
        f"\n\nLegitimate URLs:\n" +
        ("\n".join([f"{url['url']} - {url['status']}" for url in legitimate_urls]) if legitimate_urls else "None")
    )

    # Send the report via email
    try:
        send_email_with_report(
            to_email=current_user.email,
            report_content=report_content
        )
    except HTTPException as email_error:
        print(f"Email sending error: {email_error.detail}")  # Log email errors
        return {
            "success": False,
            "message": "Failed to send the report email. Please try again later."
        }
    except Exception as general_error:
        print(f"Unexpected error during email sending: {general_error}")  # Log unexpected errors
        raise HTTPException(status_code=500, detail="An unexpected error occurred while sending the email.")

    # Return success response
    return {
        "success": True,
        "message": "Report generated and sent to your email successfully."
    }

