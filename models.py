from sqlalchemy import Column, Integer, String, Enum, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import enum

# Define roles as an Enum (Updated to match database case)
class Roles(str, enum.Enum):
    USER = "USER"  # Uppercase
    ADMIN = "ADMIN"  # Uppercase

# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    role = Column(Enum(Roles), default=Roles.USER, nullable=False)  # Default to USER
    is_active = Column(Boolean, default=True)

    # Relationship to Report model
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")

# Report model
class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    site_url = Column(String, nullable=False)
    is_phishing = Column(Boolean, nullable=False, default=False)

    # Relationship back to User model
    user = relationship("User", back_populates="reports")
