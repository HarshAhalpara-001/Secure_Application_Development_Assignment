# auth.py - Enhanced JWT implementation with better security
import bcrypt
import jwt
import datetime
from sqlmodel import Session, select
from models import User, engine
from dotenv import load_dotenv
import os
import secrets
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("auth")

# Load environment variables and ensure SECRET_KEY is secure
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    if os.getenv("ENVIRONMENT") == "production":
        raise ValueError("Production environment requires a secure SECRET_KEY of at least 32 characters in .env file")
    # For development only - generate a random key
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("Generated temporary SECRET_KEY for development. Set a permanent key in .env file for production.")

# Rate limiting setup - simple in-memory implementation
login_attempts = {}
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 300  # 5 minutes in seconds

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def create_token(username: str) -> str:
    """Create a JWT token with secure parameters"""
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
        "jti": secrets.token_hex(16)  # Add unique token ID to prevent replay attacks
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def check_rate_limit(username: str) -> bool:
    """Check if the user has exceeded login attempt rate limits"""
    current_time = datetime.datetime.utcnow().timestamp()
    
    # Clean old attempts
    for user in list(login_attempts.keys()):
        if current_time - login_attempts[user]["timestamp"] > ATTEMPT_WINDOW:
            del login_attempts[user]
    
    if username not in login_attempts:
        login_attempts[username] = {"attempts": 1, "timestamp": current_time}
        return True
    
    attempts_data = login_attempts[username]
    
    # Reset if window has passed
    if current_time - attempts_data["timestamp"] > ATTEMPT_WINDOW:
        login_attempts[username] = {"attempts": 1, "timestamp": current_time}
        return True
    
    # Check if too many attempts
    if attempts_data["attempts"] >= MAX_ATTEMPTS:
        logger.warning(f"Rate limit exceeded for user {username}")
        return False
    
    # Increment attempts
    login_attempts[username]["attempts"] += 1
    return True

def authenticate_user(username: str, password: str) -> str:
    """Authenticate user with rate limiting"""
    # Check rate limiting
    if not check_rate_limit(username):
        logger.warning(f"Too many login attempts for {username}")
        return None
    
    try:
        with Session(engine) as session:
            user = session.exec(select(User).where(User.username == username)).first()
            if user and verify_password(password, user.hashed_password):
                logger.info(f"Successful login for user {username}")
                return create_token(user.username)
            else:
                logger.warning(f"Failed login attempt for user {username}")
                return None
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None

def get_user_from_token(token: str) -> User | None:
    """Validate JWT token and return User if valid"""
    if not token:
        return None
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        
        # Validate expiration time
        exp_time = payload.get("exp")
        if not exp_time or datetime.datetime.utcnow().timestamp() > exp_time:
            logger.warning("Token expired")
            return None
            
        if not username:
            return None
            
        with Session(engine) as session:
            user = session.exec(select(User).where(User.username == username)).first()
            if not user:
                logger.warning(f"Token contains invalid username: {username}")
            return user
            
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None