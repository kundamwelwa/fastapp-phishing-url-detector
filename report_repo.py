# app/repos/report_repo.py
from sqlalchemy.orm import Session
from models import Report

class ReportRepo:
    def __init__(self, db: Session):
        self.db = db

    def get_reports_by_user(self, user_id: int):
        # Query the database to get all reports for the user
        return self.db.query(Report).filter(Report.user_id == user_id).all()
