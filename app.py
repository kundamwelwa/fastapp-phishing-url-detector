from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Form, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse, JSONResponse
from starlette.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
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
async def detect_url(request: Request, detect_request: DetectRequest, db: Session = Depends(get_db)):
    url = detect_request.url

    # Validate the URL format
    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format.")
    
    try:
        print(f"Processing URL: {url}")

        # Call the model to get prediction results
        result = await predict_url(url)

        # Validate the result format
        if not isinstance(result, dict) or "features" not in result or "is_phishing" not in result:
            raise HTTPException(status_code=500, detail="Invalid response from predict_url.")
        
        # Validate the feature count
        feature_count = len(result.get("features", []))
        if feature_count != 16:
            raise ValueError(f"Feature count mismatch! Expected 16, got {feature_count}")

        # Convert is_phishing to a boolean value
        is_phishing = bool(result.get("is_phishing", [False])[0]) if isinstance(result.get("is_phishing"), list) else result.get("is_phishing", False)

        # Extract additional HTTPS/SSL details
        is_https = result.get("is_https", False)
        ssl_error = result.get("ssl_error", False)

        # Retrieve user authentication details
        cookie_token = get_cookies(request)
        if not cookie_token:
            raise HTTPException(status_code=401, detail="Unauthorized: Missing cookie token")

        current_user = await get_current_user(db, cookie_token)
        if not current_user:
            raise HTTPException(status_code=401, detail="User not found or unauthorized")

        user_id = current_user.id

        # Check if the URL has been reported before by the current user
        existing_report = db.query(Report).filter(Report.site_url == url, Report.user_id == user_id).first()

        if existing_report:
            # If the same user has already reported the URL, return the previous result
            return JSONResponse(content={
                "success": True,
                "url": url,
                "result": "phishing" if existing_report.is_phishing else "legitimate",
                "is_phishing": existing_report.is_phishing,
                "is_https": is_https,
                "ssl_error": ssl_error,
                "existing_report": True,
                "previous_result": "phishing" if existing_report.is_phishing else "legitimate"
            })

        # If the URL is reported by a different user, insert a new report
        new_report = Report(user_id=user_id, site_url=url, is_phishing=is_phishing)

        try:
            db.add(new_report)
            db.commit()
            db.refresh(new_report)
            print(f"Successfully added report for URL: {url} by user {user_id}")
        except IntegrityError as e:
            db.rollback()
            print(f"Integrity error occurred while adding URL: {url} for user {user_id}, Error: {e}")
            raise HTTPException(status_code=400, detail="Error inserting new report.")

        # Return response for the newly added report
        return JSONResponse(content={
            "success": True,
            "url": url,
            "result": "phishing" if is_phishing else "legitimate",
            "is_phishing": is_phishing,
            "is_https": is_https,
            "ssl_error": ssl_error,
            "existing_report": False
        })

    except Exception as e:
        print(f"Error during URL detection: {e}")
        raise HTTPException(status_code=500, detail=f"Error during URL detection: {str(e)}")






# Generate user report
from sqlalchemy.sql import func

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

    try:
        # Fetch user's reports from the database
        reports = db.query(Report).filter(Report.user_id == current_user.id).all()
    except Exception as db_error:
        print(f"Database error: {db_error}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user reports.")

    # Check if reports exist
    if not reports:
        return {"success": False, "message": "No reports found for this user."}

    # Categorize reports into phishing and legitimate URLs
    phishing_urls = [report.site_url for report in reports if report.is_phishing]
    legitimate_urls = [report.site_url for report in reports if not report.is_phishing]

    # Get counts
    phishing_count = len(phishing_urls)
    legitimate_count = len(legitimate_urls)

    # Construct the report content
    report_content = (
        f"Phishing Detection Report\n\n"
        f"User: {current_user.username}\n"
        f"Email: {current_user.email}\n\n"
        f"Summary:\n"
        f"- Total URLs detected: {phishing_count + legitimate_count}\n"
        f"- Phishing URLs: {phishing_count}\n"
        f"- Legitimate URLs: {legitimate_count}\n\n"
        f"Details:\n\n"
        f"Phishing URLs:\n" +
        ("\n".join(phishing_urls) if phishing_urls else "None") +
        f"\n\nLegitimate URLs:\n" +
        ("\n".join(legitimate_urls) if legitimate_urls else "None")
    )

    # Send the report via email
    try:
        send_email_with_report(
            to_email=current_user.email,
            report_content=report_content,
            phishing_count=phishing_count,
            legitimate_count=legitimate_count,
            phishing_urls=phishing_urls,  # Pass phishing URLs
            legitimate_urls=legitimate_urls  # Pass legitimate URLs
        )
    except HTTPException as email_error:
        print(f"Email sending error: {email_error.detail}")
        return {
            "success": False,
            "message": "Failed to send the report email. Please try again later."
        }
    except Exception as general_error:
        print(f"Unexpected error during email sending: {general_error}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while sending the email.")

    # Return success response
    return {
        "success": True,
        "message": "Report generated and sent to your email successfully."
    }
