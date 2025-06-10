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


from fastapi import APIRouter, HTTPException, FastAPI, Depends, Path, WebSocket, WebSocketDisconnect
from app.models.user_models import UserCreate, UserLogin, ProductCreate
from app.utils.password import hash_password, verify_password
import sqlalchemy
from dotenv import load_dotenv
from app.models.models import start_db, Category
from app.models.models import User, Product

import json
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from typing import List


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
load_dotenv()
app = FastAPI()
auth_app = FastAPI()
chat_router = APIRouter()
app.mount("/auth", auth_app)


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

#треба потім видалити
fake_products = [
    {"id": 1, "name": "Socks", "price": 10.0, "description": "Warm socks", "seller_id": 1},
    {"id": 2, "name": "T-shirt", "price": 20.0, "description": "White t-shirt", "seller_id": 2}
]

fake_users = [
    {"id": 1, "username": "anna"},
    {"id": 2, "username": "john"}
]

# Тимчасовий get_current_user (без токенів)
def get_current_user_fake():
    return fake_users[0]


active_connections: List[WebSocket] = []


def get_current_user_token(token: str, db: Session):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(db, username)
    if user:
        return user
    raise credentials_exception



@chat_router.websocket("/ws/chat/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    await websocket.accept()
    db = next(start_db())
    try:
        user = get_current_user_token(token, db)
        username = user.username
        active_connections.append(websocket)

        print(f"Username connected: {username}")
        await websocket.send_text(f"Welcome {username}! You are connected")

        while True:
            data = await websocket.receive_text()
            message_data = {
                "username": username,
                "message": data,
                "timestamp": datetime.utcnow().isoformat()
            }
            for connection in active_connections:
                await connection.send_text(json.dumps(message_data))

    except WebSocketDisconnect:
        active_connections.remove(websocket)
        print(f"Client disconnected: {websocket.client}")



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


@app.delete("/del_fake/{product_id}")
async def delete_fake_product(
    product_id: int = Path(..., gt=0),
    user: dict = Depends(get_current_user_fake)
):
    global fake_products
    product = next((p for p in fake_products if p["id"] == product_id), None)

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if product["seller_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="You are not allowed to delete this product")

    fake_products = [p for p in fake_products if p["id"] != product_id]
    return {"msg": f"Product {product_id} deleted successfully"}






