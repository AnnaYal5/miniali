import os
import sys
from datetime import timedelta, datetime
from typing import Annotated
from jwt.exceptions import InvalidTokenError
import jwt
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from starlette import status

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


from fastapi import APIRouter, HTTPException, FastAPI, Depends
from app.models.user_models import UserCreate, UserLogin, ProductCreate
from app.utils.password import hash_password, verify_password
import sqlalchemy
from dotenv import load_dotenv
from app.models.models import start_db, Category
from app.models.models import User, Product
load_dotenv()


app = FastAPI()

auth_app = FastAPI()

app.mount("/auth", auth_app)
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_user(db, username: str):
    db_user: User = db.query(User).filter(User.username == username).first()
    if db_user:
        return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=60)
    to_encode.update({'exp': expire})
    encoded = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(start_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"})
    try:
        payload: dict = jwt.decode(token, SECRET_KEY, ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(db, username)
    if user:
        return user
    raise credentials_exception


@auth_app.post("/register")
async def register(user: UserCreate, db: Session = Depends(start_db)):
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_password = hash_password(user.password)
    n_user = User(username = user.username,
                hashed_password = hashed_password,
                email = user.email)
    db.add(n_user)
    db.commit()
    return {"msg": "Registered"}

@auth_app.post("/token")
async def login(user: UserLogin, db: Session = Depends(start_db)):
    db_user: User = authenticate_user(db, user.username, user.password)
    if db_user:
        access_token = create_token(data={"sub": db_user.username})
        return {"access_token": access_token, "token_type": "bearer"}


@app.get('/')
async def products(db: Session = Depends(start_db)):
    to_show = db.query(Product).all()
    return [to_show]

@app.get("/users/me")
async def current_user_me(current_user: User = Depends(get_current_user)):
    return {"user": current_user}


@app.post("/add")
async def add_products(product: ProductCreate, user: User = Depends(get_current_user), db: Session = Depends(start_db)):
    category_db: Category = db.query(Category).filter(product.category == Category.name).first()
    new_product = Product(
        name=product.name,
        price=product.price,
        description=product.description,
        seller_id=user.id
    )
    if category_db:
        new_product.category = category_db.name
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return {"msg": "added"}


@app.delete("/del")
def delete():
    pass






