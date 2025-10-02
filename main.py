import os
from dotenv import load_dotenv
load_dotenv() # This loads the variables from your .env file
import resend
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import (or_, Boolean, Column, DateTime, ForeignKey, Integer, String, create_engine)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# --- CONFIGURATIONS ---

# Database
SQLALCHEMY_DATABASE_URL = "sqlite:///./food_redistribute.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Resend Email
RESEND_API_KEY = os.getenv("RESEND_API_KEY")  # Replace with your actual key
resend.api_key = RESEND_API_KEY

# Authentication
SECRET_KEY = "a_super_secret_key_for_our_food_project"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# --- DATABASE MODELS ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    organization_name = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="donor")
        # Add these two new columns
    otp = Column(String, nullable=True)
    otp_expiry = Column(DateTime(timezone=True), nullable=True)

class SurplusFood(Base):
    __tablename__ = "surplus_food"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    quantity = Column(String)
    location = Column(String)
    expiry_date = Column(DateTime)
    status = Column(String, default="available")
    donor_id = Column(Integer, ForeignKey("users.id"))
    claimed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True) # FIXED


# --- PYDANTIC SCHEMAS ---

class UserSchema(BaseModel):
    id: int
    email: EmailStr
    role: str
    organization_name: str | None = None

    class Config:
        from_attributes = True

class OtpVerify(BaseModel):
    email: EmailStr
    otp: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "donor"
    organization_name: str

class SurplusFoodBase(BaseModel):
    title: str
    quantity: str
    location: str
    expiry_date: datetime

class SurplusFoodCreate(SurplusFoodBase):
    pass

class SurplusFoodSchema(SurplusFoodBase):
    id: int
    donor_id: int
    status: str
    claimed_by_id: int | None = None # UPDATED

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None


# --- HELPER & CRUD FUNCTIONS ---

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user_data: dict):
    hashed_password = get_password_hash(user_data['password'])
    db_user = User(
        email=user_data['email'],
        hashed_password=hashed_password,
        role=user_data['role'],
        organization_name=user_data['organization_name']
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


# --- FASTAPI APP INITIALIZATION ---

app = FastAPI(title="FoodRedistribute API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


# --- API ENDPOINTS ---

@app.get("/")
def read_root():
    return {"Status": "API is running"}

# --- Authentication Endpoints ---

@app.post("/auth/register", response_model=UserSchema)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db=db, user_data=user.model_dump())

@app.post("/auth/login") # The response_model=Token is removed
def login_for_otp(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    # Generate and save OTP
    otp = str(random.randint(100000, 999999))
    user.otp = otp # For production, you should hash this OTP
    user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()

    # Send OTP email
    try:
        params = {
            "from": "onboarding@resend.dev",
            "to": [user.email],
            "subject": "Your FoodRedistribute Login OTP",
            "html": f"<h1>Your OTP is: {otp}</h1><p>It will expire in 10 minutes.</p>"
        }
        resend.Emails.send(params)
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send OTP.")

    return {"message": "OTP has been sent to your email."}

@app.post("/auth/verify-otp", response_model=Token)
def verify_otp_and_login(
    otp_data: OtpVerify,
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email=otp_data.email)

    # Check for user, valid OTP, and expiry
    if not user or user.otp != otp_data.otp or user.otp_expiry < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP or OTP expired",
        )

    # Clear OTP after successful verification
    user.otp = None
    user.otp_expiry = None
    db.commit()

    # Create and return the final access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Surplus Food Endpoints ---

@app.post("/surplus", response_model=SurplusFoodSchema)
def create_surplus_food_item(
    food: SurplusFoodCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    food_dict = food.model_dump()
    new_food_item = SurplusFood(**food_dict, donor_id=current_user.id)
    db.add(new_food_item)
    db.commit()
    db.refresh(new_food_item)

    try:
        params = {
            "from": "onboarding@resend.dev",
            "to": ["dnyanp300@gmail.com"], # IMPORTANT: Replace
            "subject": f"New Food Donation Available: {new_food_item.title}",
            "html": f"<h1>New Food Donation!</h1><p>Details: {new_food_item.title}, {new_food_item.quantity}, at {new_food_item.location}.</p>"
        }
        resend.Emails.send(params)
        print("Notification email sent.")
    except Exception as e:
        print(f"Failed to send email: {e}")

    return new_food_item

@app.get("/surplus", response_model=list[SurplusFoodSchema])
def get_available_food(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(SurplusFood).filter(SurplusFood.status == "available").all()

@app.get("/history", response_model=list[SurplusFoodSchema])
def get_user_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # FIXED: Now returns items donated BY or claimed BY the current user
    history = db.query(SurplusFood).filter(
        or_(
            SurplusFood.donor_id == current_user.id,
            SurplusFood.claimed_by_id == current_user.id
        )
    ).all()
    return history

@app.post("/surplus/{item_id}/claim", response_model=SurplusFoodSchema)
def claim_surplus_food_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    food_item = db.query(SurplusFood).filter(SurplusFood.id == item_id).first()
    if not food_item:
        raise HTTPException(status_code=404, detail="Food item not found")
    if food_item.status != "available":
        raise HTTPException(status_code=400, detail="Food item is no longer available")
    
    food_item.status = "claimed"
    food_item.claimed_by_id = current_user.id # FIXED
    db.commit()
    db.refresh(food_item)
    return food_item

@app.post("/surplus/{item_id}/confirm_delivery", response_model=SurplusFoodSchema)
def confirm_delivery(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    food_item = db.query(SurplusFood).filter(SurplusFood.id == item_id).first()
    if not food_item:
        raise HTTPException(status_code=404, detail="Food item not found")
    if food_item.status != "claimed":
        raise HTTPException(status_code=400, detail="This item cannot be marked as delivered.")
    # You could add a check here to ensure only the claiming user can confirm
    # if food_item.claimed_by_id != current_user.id:
    #     raise HTTPException(status_code=403, detail="Not authorized to confirm this delivery")
    food_item.status = "delivered"
    db.commit()
    db.refresh(food_item)
    return food_item

@app.post("/surplus/{item_id}/find-matches", response_model=list[UserSchema])
def find_matches_for_surplus_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    food_item = db.query(SurplusFood).filter(SurplusFood.id == item_id).first()
    if not food_item:
        raise HTTPException(status_code=404, detail="Food item not found")
    
    volunteers = db.query(User).filter(User.role == "volunteer").all()
    if not volunteers:
        return []

    try:
        food_location_keyword = food_item.location.split(',')[0].strip().lower()
        matches = [
            v for v in volunteers 
            if food_location_keyword in v.organization_name.lower()
        ]
        return matches
    except Exception:
        return []