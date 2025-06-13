from collections import Counter
from typing import List

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime, func, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Mapped
#metadata = Base.metadata

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)
LocalSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(16), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())
    orders: Mapped[List["Order"]] = relationship(back_populates="buyer")
    products: Mapped[List['Product']] = relationship(back_populates='seller')
    is_admin = Column(Boolean, nullable=False)

class Order(Base):
    __tablename__ = "order"
    id = Column(Integer, primary_key=True)
    buyer_id = Column(ForeignKey("user.id"))
    buyer: Mapped["User"] = relationship(back_populates="orders")

class Product(Base):
    __tablename__ = "product"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    price: float = Column(Float, nullable=False)
    description = Column(String(512), nullable=False)
    seller_id = Column(ForeignKey('user.id'))
    seller: Mapped['User'] = relationship(back_populates='products')
    category_id = Column(ForeignKey('category.id'))
    category: Mapped['Category'] = relationship(back_populates='products')


class Category(Base):
    __tablename__ = "category"
    id = Column(Integer, primary_key=True)
    name = Column(String(16), nullable=False)
    products: Mapped[List['Product']] = relationship(back_populates='category')


def start_db():
    db = LocalSession()
    try:
        yield db
    finally:
        db.close()