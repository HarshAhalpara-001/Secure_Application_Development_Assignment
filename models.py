from sqlmodel import SQLModel, Field, create_engine, Session, Relationship
from typing import Optional, List
from contextlib import contextmanager
from datetime import datetime
import os
from dotenv import load_dotenv
from pydantic import field_validator, EmailStr, ConfigDict
import re

# Load environment variables
load_dotenv()

# Get database connection from environment or use SQLite as fallback
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# Configure engine with appropriate settings
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=(os.getenv("SQL_ECHO", "false").lower() == "true"),
    pool_pre_ping=not DATABASE_URL.startswith("sqlite")
)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, nullable=False, min_length=3, max_length=30)
    email: EmailStr = Field(unique=True, nullable=False)
    hashed_password: str = Field(nullable=False)
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"server_default": "CURRENT_TIMESTAMP"}
    )
    user_data: List["UserData"] = Relationship(back_populates="user")
    
    model_config = ConfigDict(extra="forbid")
    
    @field_validator('username')
    @classmethod
    def username_must_be_valid(cls, v: str) -> str:
        if not re.match(r'^[A-Za-z0-9_-]+$', v):
            raise ValueError('Username must contain only letters, numbers, underscores, and hyphens')
        return v

class UserData(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    creation_date: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"server_default": "CURRENT_TIMESTAMP"}
    )
    data_content: str = Field(nullable=False, max_length=1000)
    user: User = Relationship(back_populates="user_data")
    
    model_config = ConfigDict(extra="forbid")
    
    @field_validator('data_content')
    @classmethod
    def data_content_must_be_valid(cls, v: str) -> str:
        if not v.strip():
            raise ValueError('Data content cannot be empty or whitespace')
        return v

def create_db() -> None:
    """Create database tables if they don't exist"""
    # Drop all tables first to ensure clean migration
    SQLModel.metadata.drop_all(engine)  # Uncomment if you want to reset DB
    SQLModel.metadata.create_all(engine)
    
    # Set file permissions for SQLite
    if DATABASE_URL.startswith("sqlite:///"):
        db_file = DATABASE_URL.replace("sqlite:///", "")
        try:
            os.chmod(db_file, 0o600)  # Secure file permissions
        except Exception as e:
            print(f"Warning: Could not set database file permissions: {e}")

@contextmanager
def get_session():
    """Context manager for database sessions with error handling"""
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()