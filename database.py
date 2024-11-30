from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Define SQLite database URL
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.abspath('./db.sqlite')}"

# Create the engine
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

# Session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base for models
Base = declarative_base()

# Dependency for accessing the database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
