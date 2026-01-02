from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import List
from passlib.context import CryptContext
import os

# --------------------------------------------------
# App & Templates
# --------------------------------------------------
app = FastAPI(title="FastAPI + Jinja + JWT (sessionStorage)")
templates = Jinja2Templates(directory="templates")

# --------------------------------------------------
# Database (SQLite)
# --------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_args = {}
if DATABASE_URL.startswith("sqlite"):
    engine_args = {"connect_args": {"check_same_thread": False}}

engine = create_engine(DATABASE_URL, **engine_args)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)  # hashed

Base.metadata.create_all(bind=engine)

# --------------------------------------------------
# DB Dependency
# --------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --------------------------------------------------
# Password Hashing (Pydroid-safe)
# --------------------------------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)

# --------------------------------------------------
# JWT Config
# --------------------------------------------------
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# --------------------------------------------------
# Pydantic Models
# --------------------------------------------------
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    email: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    model_config = {"from_attributes": True}

# --------------------------------------------------
# AUTH DEPENDENCY
# --------------------------------------------------
def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = creds.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================================================
# API ROUTES
# ==================================================

@app.post("/api/users", status_code=201)
def api_create_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email exists")

    new_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created", "user_id": new_user.id}

@app.post("/api/login", response_model=LoginResponse)
def api_login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email
    }

@app.get("/api/dashboard/users", response_model=List[UserOut])
def api_dashboard_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(User).all()

# ==================================================
# PAGE ROUTES (JINJA)
# ==================================================

@app.get("/", response_class=HTMLResponse)
def page_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
def page_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def page_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})
