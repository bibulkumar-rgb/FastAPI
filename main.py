from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import List
from passlib.context import CryptContext

# --------------------------------------------------
# App
# --------------------------------------------------
app = FastAPI(title="Simple JWT App (HTTP Bearer)")

# --------------------------------------------------
# Database (SQLite)
# --------------------------------------------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
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
# DB dependency
# --------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --------------------------------------------------
# Password hashing (Pydroid-safe)
# --------------------------------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# --------------------------------------------------
# JWT config
# --------------------------------------------------
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()   # 👈 CLEAN BEARER AUTH

# --------------------------------------------------
# Pydantic models
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
# JWT helper
# --------------------------------------------------
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# --------------------------------------------------
# Index
# --------------------------------------------------
@app.get("/")
def index():
    return {"message": "Welcome to FastAPI JWT Demo"}

# --------------------------------------------------
# Create user
# --------------------------------------------------
@app.post("/users", status_code=201)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already exists")

    new_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User created successfully",
        "user_id": new_user.id
    }

# --------------------------------------------------
# Login (JWT create)
# --------------------------------------------------
@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    token = create_access_token({"sub": user.email})

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email
    }

# --------------------------------------------------
# JWT validation (reads Authorization: Bearer)
# --------------------------------------------------
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --------------------------------------------------
# Dashboard (protected)
# --------------------------------------------------
@app.get("/dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Welcome {current_user.username}",
        "email": current_user.email
    }

# --------------------------------------------------
# Get all users (protected)
# --------------------------------------------------
@app.get("/dashboard/users", response_model=List[UserOut])
def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(User).all()
