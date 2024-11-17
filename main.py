from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.future import select
from passlib.context import CryptContext
from typing import List
from datetime import datetime, timedelta
import jwt
import redis
import uvicorn
from fastapi.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

# FastAPI app initialization
app = FastAPI()

# OAuth2 configuration to specify the token URL for OAuth2 authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database connection setup for PostgreSQL using asyncpg with SQLAlchemy
DATABASE_URL = "postgresql+asyncpg://postgres:yourpassword@localhost/tenant_db"
DATABASE_ENGINE = create_async_engine(DATABASE_URL, echo=True)

# JWT Settings - Use these to encode and decode JWT tokens
SECRET_KEY = "yoursecretkey"  # Use a strong secret key in production!
ALGORITHM = "HS256"  # Algorithm used to encode and decode the JWT token
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Set JWT expiration time (30 minutes)

# Redis session configuration for managing sessions
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

# SQLAlchemy Base Model definition
Base = declarative_base()

# Password hashing utility using passlib for secure password storage
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency to get the session for interacting with the database
async def get_db():
    """
    Database dependency to fetch the database session. This is used
    in various routes to interact with the database (CRUD operations).
    """
    # Establish an async database connection using SQLAlchemy
    async with DATABASE_ENGINE.connect() as connection:
        async_session = sessionmaker(
            bind=connection, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            yield session  # Yield the session to be used in API route

# Define the database models for users and tenants
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))

    # Relationship to the Tenant model
    tenant = relationship("Tenant", back_populates="users")

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

    # Relationship to the User model
    users = relationship("User", back_populates="tenant")

# Utility functions to hash and verify passwords
def hash_password(password: str):
    """
    Hashes a plain password using bcrypt. This is used for securely storing
    user passwords in the database.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    """
    Verifies that a plain password matches the hashed version. Used during
    the login process to validate user credentials.
    """
    return pwd_context.verify(plain_password, hashed_password)

# Function to create a JWT token with expiration time
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    """
    Creates a JWT access token with the specified data and expiration time.
    The token will include a claim for expiration (`exp`).
    """
    to_encode = data.copy()  # Create a copy of the input data to encode
    expire = datetime.utcnow() + expires_delta  # Set expiration time
    to_encode.update({"exp": expire})  # Add the expiration claim
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # Encode the data into a JWT
    return encoded_jwt

# Function to verify and decode the JWT token
def verify_jwt_token(token: str):
    """
    Verifies and decodes the JWT token to extract the payload.
    Returns the decoded payload if the token is valid, or None if invalid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Decode the token
        return payload  # Return the decoded payload
    except jwt.PyJWTError:
        return None  # Return None if the token is invalid

# Redis session management middleware to handle session persistence
class RedisSessionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle session persistence using Redis. This middleware
    checks for a session token in the request cookies and fetches user data
    from Redis. It also handles rolling session expiration (TTL extension).
    """
    async def dispatch(self, request: Request, call_next):
        # Retrieve session token from cookies
        session_token = request.cookies.get("session_token")
        if session_token:
            # Check if user data exists in Redis for the session token
            user_data = redis_client.get(session_token)
            if user_data:
                # Renew the session expiration time (rolling renewal) by updating TTL
                redis_client.expire(session_token, 60 * 30)  # Extend TTL by 30 minutes
                request.state.user = user_data  # Attach user data to the request state
        response = await call_next(request)  # Continue processing the request
        return response

# API Route to create a new tenant and user
@app.post("/create_tenant/")
async def create_tenant_and_user(user_create: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Creates a new tenant and user in the database. If the tenant does not
    already exist, it is created along with the user.
    """
    tenant = await db.execute(select(Tenant).filter_by(name=user_create.tenant_name))
    tenant = tenant.scalar_one_or_none()  # Fetch the tenant or None if not found
    
    if not tenant:
        # If the tenant doesn't exist, create it
        tenant = Tenant(name=user_create.tenant_name)
        db.add(tenant)
        await db.commit()  # Commit the transaction
    
    # Hash the user's password before saving it in the database
    hashed_password = hash_password(user_create.password)
    
    # Create a new user and associate it with the tenant
    new_user = User(username=user_create.username, email=user_create.email,
                    hashed_password=hashed_password, tenant_id=tenant.id)
    
    # Add the user to the session and commit the transaction
    db.add(new_user)
    await db.commit()
    
    return {"message": "User and tenant created successfully!"}

# API Route for login (JWT token generation)
@app.post("/token/")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """
    Handles user login by verifying credentials, creating a JWT token, and
    generating a session token stored in Redis.
    """
    # Check if the user exists in the database
    user = await db.execute(select(User).filter_by(username=form_data.username))
    user = user.scalar_one_or_none()
    
    # If user doesn't exist or password doesn't match, raise an error
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create a JWT access token for the user
    access_token = create_access_token(data={"sub": user.username})
    
    # Create a session token for the user and store it in Redis with a TTL of 30 minutes
    session_token = f"session_{user.username}"
    redis_client.set(session_token, user.username, ex=60*30)  # Set initial TTL to 30 minutes

    # Create a response containing the JWT token and session token in the cookies
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer", "session_token": session_token})
    response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=60*30, expires=60*30)
    
    return response

# Main entry point to create database tables on startup
@app.on_event("startup")
async def on_startup():
    """
    Creates the necessary database tables on application startup.
    This is done by calling `Base.metadata.create_all()`.
    """
    async with DATABASE_ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Create tables

# Apply the Redis session management middleware to the app
app.add_middleware(RedisSessionMiddleware)

# Route to get current authenticated user
@app.get("/users/me")
async def get_me(request: Request):
    """
    Fetches the currently authenticated user based on the session token
    or JWT token. Returns user data if authenticated, or raises an error.
    """
    if hasattr(request.state, 'user'):
        return {"user": request.state.user}  # Return user info
    raise HTTPException(status_code=401, detail="Not authenticated")  # Raise error if not authenticated

# Run the app using uvicorn for local development
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
