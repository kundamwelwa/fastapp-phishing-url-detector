from sqlalchemy.orm import Session
from models import Report
from typing import List, Optional

class ReportRepo:
    def __init__(self, db: Session):
        self.db = db

    def get_reports_by_user(self, user_id: int, limit: Optional[int] = 10, skip: Optional[int] = 0) -> List[Report]:
        """
        Fetch reports for a specific user with pagination.
        
        :param user_id: The ID of the user whose reports are being fetched.
        :param limit: The maximum number of reports to fetch (default is 10).
        :param skip: The number of reports to skip (default is 0).
        :return: A list of reports.
        """
        try:
            # Query the database to get reports for the user with pagination
            reports = self.db.query(Report).filter(Report.user_id == user_id).offset(skip).limit(limit).all()

            # If no reports are found, return an empty list
            if not reports:
                return []

            return reports
        except Exception as e:
            # Log the error (you can replace this print statement with a logger)
            print(f"Error fetching reports for user {user_id}: {e}")
            # Optionally, raise an exception or return an empty list
            raise Exception(f"Failed to fetch reports for user {user_id}. Error: {str(e)}")
