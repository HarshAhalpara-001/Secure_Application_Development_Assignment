from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import strawberry
from strawberry.fastapi import GraphQLRouter
from sqlmodel import select, Session
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
import re
import bleach
from models import User, UserData, create_db, get_session
from auth import get_user_from_token, authenticate_user, hash_password
import os
from typing import Optional, Dict, Any, List
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("app")

# Configure rate limiting
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI application
app = FastAPI(
    title="Secure User Data API",
    description="A secure FastAPI application for managing user data",
    version="1.0.0"
)

# Register rate limit exceeded handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Get allowed origins from environment or use defaults
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", 
    "http://localhost:8000,http://127.0.0.1:8000"
).split(",")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)

templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

# Input validation models
class RegisterUserInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=8)
    
    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r'^[A-Za-z0-9_-]+$', v):
            raise ValueError('Username must contain only letters, numbers, underscores, and hyphens')
        return v
        
    @field_validator('password')
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        return v

class LoginInput(BaseModel):
    username: str
    password: str

# GraphQL Types
@strawberry.type
class UserType:
    id: strawberry.ID
    username: str
    email: str

@strawberry.type
class UserDataType:
    id: strawberry.ID
    user_id: int = strawberry.field(name="userId")  # Map to camelCase
    creation_date: str = strawberry.field(name="creationDate")  # Map to camelCase
    data_content: str = strawberry.field(name="dataContent")  # Map to camelCase

@strawberry.type
class LoginResponse:
    token: Optional[str]
    message: str

# Context management
async def get_context(request: Request, response: Response):
    return {"request": request, "response": response}

def get_current_user(request: Request) -> User:
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return user

# Sanitize HTML content
def sanitize_content(content: str) -> str:
    """Sanitize user input to prevent XSS attacks"""
    return bleach.clean(
        content,
        tags=[],  # No HTML tags allowed
        strip=True
    )

# GraphQL Schema
@strawberry.type
class Query:
    @strawberry.field
    async def get_current_user(self, info) -> UserType:
        """Get the currently authenticated user"""
        request = info.context["request"]
        user = get_current_user(request)
        return UserType(
            id=strawberry.ID(str(user.id)),
            username=user.username,
            email=user.email
        )

    @strawberry.field
    async def get_user_data(self, info) -> List[UserDataType]:
        """Get all data items for the current user"""
        request = info.context["request"]
        user = get_current_user(request)
        
        with get_session() as session:
            user_data = session.exec(select(UserData).where(UserData.user_id == user.id)).all()
            return [
                UserDataType(
                    id=strawberry.ID(str(d.id)),
                    user_id=d.user_id,
                    creation_date=d.creation_date.isoformat(),
                    data_content=d.data_content
                ) for d in user_data
            ]

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def register_user(
        self, 
        info,
        username: str, 
        email: str, 
        password: str
    ) -> UserType:
        """Register a new user with validation"""
        request = info.context["request"]
        
        # Validate input
        input_data = RegisterUserInput(username=username, email=email, password=password)
        
        with get_session() as session:
            # Check if username or email already exists
            existing_user = session.exec(
                select(User).where((User.username == username) | (User.email == email))
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    raise Exception("Username already exists")
                else:
                    raise Exception("Email already exists")
            
            # Create new user with hashed password
            hashed_password = hash_password(password)
            new_user = User(
                username=username,
                email=email,
                hashed_password=hashed_password
            )
            
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            
            logger.info(f"New user registered: {username}")
            
            return UserType(
                id=strawberry.ID(str(new_user.id)),
                username=new_user.username,
                email=new_user.email
            )

    @strawberry.mutation
    async def login(self, info, username: str, password: str) -> LoginResponse:
        """Log in a user and return JWT token in HTTP-only cookie"""
        response = info.context["response"]
        
        token = authenticate_user(username, password)
        
        if token:
            # Set secure HTTP-only cookie with the token
            response.set_cookie(
                key="token",
                value=token,
                httponly=True,
                secure=os.getenv("ENVIRONMENT") == "production",
                samesite="lax",
                max_age=7200,
                path="/"
            )
            return LoginResponse(token=None, message="Login successful")
        else:
            return LoginResponse(token=None, message="Invalid username or password")

    @strawberry.mutation
    async def add_user_data(self, info, data_content: str) -> UserDataType:
        """Add a new data item for the current user"""
        request = info.context["request"]
        user = get_current_user(request)
        
        # Sanitize input
        sanitized_content = sanitize_content(data_content)
        
        with get_session() as session:
            user_data = UserData(user_id=user.id, data_content=sanitized_content)
            session.add(user_data)
            session.commit()
            session.refresh(user_data)
            
            logger.info(f"User {user.username} added new data item")
            
            return UserDataType(
                id=strawberry.ID(str(user_data.id)),
                user_id=user_data.user_id,
                creation_date=user_data.creation_date.isoformat(),
                data_content=user_data.data_content
            )

    @strawberry.mutation
    async def update_user_data(self, info, data_id: strawberry.ID, data_content: str) -> UserDataType:
        """Update an existing data item"""
        request = info.context["request"]
        user = get_current_user(request)
        
        # Sanitize input
        sanitized_content = sanitize_content(data_content)
        
        with get_session() as session:
            user_data = session.exec(select(UserData).where(UserData.id == int(data_id))).first()
            if not user_data:
                raise Exception("Data item not found")
                
            if user_data.user_id != user.id:
                logger.warning(f"User {user.username} attempted to modify data belonging to user_id {user_data.user_id}")
                raise Exception("Unauthorized to modify this data")
                
            user_data.data_content = sanitized_content
            session.add(user_data)
            session.commit()
            session.refresh(user_data)
            
            logger.info(f"User {user.username} updated data item {data_id}")
            
            return UserDataType(
                id=strawberry.ID(str(user_data.id)),
                user_id=user_data.user_id,
                creation_date=user_data.creation_date.isoformat(),
                data_content=user_data.data_content
            )

    @strawberry.mutation
    async def delete_user_data(self, info, data_id: strawberry.ID) -> bool:
        """Delete a data item"""
        request = info.context["request"]
        user = get_current_user(request)
        
        with get_session() as session:
            user_data = session.exec(select(UserData).where(UserData.id == int(data_id))).first()
            if not user_data:
                raise Exception("Data item not found")
                
            if user_data.user_id != user.id:
                logger.warning(f"User {user.username} attempted to delete data belonging to user_id {user_data.user_id}")
                raise Exception("Unauthorized to delete this data")
                
            session.delete(user_data)
            session.commit()
            
            logger.info(f"User {user.username} deleted data item {data_id}")
            
            return True

schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_app = GraphQLRouter(
    schema,
    context_getter=get_context,
    graphiql=True
)

app.include_router(graphql_app, prefix="/graphql")

# Create database tables
create_db()

# Routes
@app.get("/")
@limiter.limit("10/minute")
async def register_page(request: Request):
    """Serve registration page"""
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/login")
@limiter.limit("10/minute")
async def login_page(request: Request):
    """Serve login page"""
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard")
async def dashboard(request: Request):
    """Serve dashboard page with authentication check"""
    try:
        # Verify token exists and is valid
        token = request.cookies.get("token")
        if not token or not get_user_from_token(token):
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        return templates.TemplateResponse("dashboard.html", {"request": request})
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}")
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# Logout endpoint
@app.get("/logout")
async def logout():
    """Log out user by clearing token cookie"""
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="token", path="/")
    return response

if __name__ == "__main__":
    import uvicorn
    
    # Use environment variables for host and port if available
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    
    # Only run development server if explicitly called
    uvicorn.run(
        "main:app", 
        host=host, 
        port=port, 
        reload=os.getenv("ENVIRONMENT") != "production"
    )