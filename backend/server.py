import os
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from pymongo.collection import Collection
from bson.json_util import dumps
import json
from dotenv import load_dotenv
import matplotlib.pyplot as plt
import pandas as pd
import base64
from io import BytesIO
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Load environment variables
load_dotenv()

# Set up MongoDB connection
mongo_url = os.environ.get("MONGO_URL")
client = MongoClient(mongo_url)
db = client.expense_tracker

# Set up FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")
SECRET_KEY = os.environ.get("SECRET_KEY", "your_secret_key_here_please_change_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# ------------------------
# Models
# ------------------------

class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str
    created_at: datetime
    
    class Config:
        orm_mode = True

class ExpenseCategory(BaseModel):
    id: str
    name: str
    user_id: Optional[str] = None  # None for preset categories
    
    class Config:
        orm_mode = True

class ExpenseBase(BaseModel):
    amount: float
    description: str
    category_id: str
    date: datetime

class ExpenseCreate(ExpenseBase):
    pass

class Expense(ExpenseBase):
    id: str
    user_id: str
    created_at: datetime
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

class ThemeSettings(BaseModel):
    user_id: str
    color_theme: str = "blue"  # blue, purple, green, orange
    mode: str = "light"  # light, dark
    
    class Config:
        orm_mode = True

# ------------------------
# Helper functions
# ------------------------

def get_user_collection() -> Collection:
    return db.users

def get_expense_collection() -> Collection:
    return db.expenses

def get_category_collection() -> Collection:
    return db.categories

def get_theme_collection() -> Collection:
    return db.themes

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str):
    user_collection = get_user_collection()
    user = user_collection.find_one({"email": email})
    if user:
        user["id"] = str(user["_id"])
        return user
    return None

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    
    user_collection = get_user_collection()
    user = user_collection.find_one({"_id": token_data.user_id})
    if user is None:
        raise credentials_exception
    
    user["id"] = str(user["_id"])
    return user

# Function to create preset categories
def create_preset_categories():
    category_collection = get_category_collection()
    preset_categories = [
        {"name": "Groceries", "user_id": None},
        {"name": "Entertainment", "user_id": None},
        {"name": "Restaurants", "user_id": None},
        {"name": "Uber/Lyft", "user_id": None},
        {"name": "Auto", "user_id": None},
        {"name": "Insurance", "user_id": None},
        {"name": "Housing", "user_id": None},
        {"name": "Utilities", "user_id": None},
        {"name": "Healthcare", "user_id": None},
        {"name": "Education", "user_id": None}
    ]
    
    # Check if preset categories already exist
    if category_collection.count_documents({"user_id": None}) == 0:
        for category in preset_categories:
            category["_id"] = str(uuid.uuid4())
            category_collection.insert_one(category)

# Call function to create preset categories
create_preset_categories()

# ------------------------
# Authentication routes
# ------------------------

@app.post("/api/register", response_model=User)
async def register(user: UserCreate):
    user_collection = get_user_collection()
    
    existing_user = user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_id = str(uuid.uuid4())
    user_data = {
        "_id": user_id,
        "email": user.email,
        "username": user.username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    }
    
    user_collection.insert_one(user_data)
    
    # Create default theme for user
    theme_collection = get_theme_collection()
    theme_data = {
        "_id": str(uuid.uuid4()),
        "user_id": user_id,
        "color_theme": "blue",
        "mode": "light"
    }
    theme_collection.insert_one(theme_data)
    
    # Return user without password
    return {
        "id": user_id,
        "email": user.email,
        "username": user.username,
        "created_at": user_data["created_at"]
    }

@app.post("/api/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["_id"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/me", response_model=User)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "username": current_user["username"],
        "created_at": current_user["created_at"]
    }

# ------------------------
# Theme routes
# ------------------------

@app.get("/api/theme")
async def get_user_theme(current_user: dict = Depends(get_current_user)):
    theme_collection = get_theme_collection()
    theme = theme_collection.find_one({"user_id": current_user["id"]})
    
    if not theme:
        # Create default theme if not exists
        theme_id = str(uuid.uuid4())
        theme = {
            "_id": theme_id,
            "user_id": current_user["id"],
            "color_theme": "blue",
            "mode": "light"
        }
        theme_collection.insert_one(theme)
    
    theme["id"] = str(theme["_id"])
    return theme

@app.put("/api/theme")
async def update_user_theme(theme_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    theme_collection = get_theme_collection()
    
    # Find existing theme
    existing_theme = theme_collection.find_one({"user_id": current_user["id"]})
    
    if existing_theme:
        # Update existing theme
        theme_collection.update_one(
            {"_id": existing_theme["_id"]},
            {"$set": {
                "color_theme": theme_data.get("color_theme", "blue"),
                "mode": theme_data.get("mode", "light")
            }}
        )
    else:
        # Create new theme
        theme_id = str(uuid.uuid4())
        new_theme = {
            "_id": theme_id,
            "user_id": current_user["id"],
            "color_theme": theme_data.get("color_theme", "blue"),
            "mode": theme_data.get("mode", "light")
        }
        theme_collection.insert_one(new_theme)
    
    # Get updated theme
    updated_theme = theme_collection.find_one({"user_id": current_user["id"]})
    updated_theme["id"] = str(updated_theme["_id"])
    return updated_theme

# ------------------------
# Category routes
# ------------------------

@app.get("/api/categories")
async def get_categories(current_user: dict = Depends(get_current_user)):
    category_collection = get_category_collection()
    
    # Get both preset categories and user's custom categories
    categories = list(category_collection.find({
        "$or": [
            {"user_id": None},
            {"user_id": current_user["id"]}
        ]
    }))
    
    # Format the categories
    formatted_categories = []
    for category in categories:
        formatted_categories.append({
            "id": str(category["_id"]),
            "name": category["name"],
            "user_id": category.get("user_id")
        })
    
    return formatted_categories

@app.post("/api/categories", response_model=ExpenseCategory)
async def create_category(category_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    category_collection = get_category_collection()
    
    # Check if category with same name already exists
    existing_category = category_collection.find_one({
        "name": category_data["name"],
        "$or": [
            {"user_id": None},
            {"user_id": current_user["id"]}
        ]
    })
    
    if existing_category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Category with this name already exists"
        )
    
    # Create new category
    category_id = str(uuid.uuid4())
    new_category = {
        "_id": category_id,
        "name": category_data["name"],
        "user_id": current_user["id"]
    }
    
    category_collection.insert_one(new_category)
    
    return {
        "id": category_id,
        "name": new_category["name"],
        "user_id": new_category["user_id"]
    }

@app.put("/api/categories/{category_id}")
async def update_category(category_id: str, category_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    category_collection = get_category_collection()
    
    # Get category
    category = category_collection.find_one({"_id": category_id})
    
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Check if user owns this category
    if category.get("user_id") != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this category"
        )
    
    # Update category
    category_collection.update_one(
        {"_id": category_id},
        {"$set": {"name": category_data["name"]}}
    )
    
    # Get updated category
    updated_category = category_collection.find_one({"_id": category_id})
    
    return {
        "id": str(updated_category["_id"]),
        "name": updated_category["name"],
        "user_id": updated_category["user_id"]
    }

@app.delete("/api/categories/{category_id}")
async def delete_category(category_id: str, current_user: dict = Depends(get_current_user)):
    category_collection = get_category_collection()
    expense_collection = get_expense_collection()
    
    # Get category
    category = category_collection.find_one({"_id": category_id})
    
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Check if user owns this category
    if category.get("user_id") != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this category"
        )
    
    # Check if category is being used by any expense
    if expense_collection.find_one({"category_id": category_id}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete category that is being used by expenses"
        )
    
    # Delete category
    category_collection.delete_one({"_id": category_id})
    
    return {"message": "Category deleted successfully"}

# ------------------------
# Expense routes
# ------------------------

@app.get("/api/expenses")
async def get_expenses(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    category_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    expense_collection = get_expense_collection()
    
    # Build filter
    filter_query = {"user_id": current_user["id"]}
    
    if start_date and end_date:
        filter_query["date"] = {
            "$gte": datetime.fromisoformat(start_date),
            "$lte": datetime.fromisoformat(end_date)
        }
    elif start_date:
        filter_query["date"] = {"$gte": datetime.fromisoformat(start_date)}
    elif end_date:
        filter_query["date"] = {"$lte": datetime.fromisoformat(end_date)}
    
    if category_id:
        filter_query["category_id"] = category_id
    
    # Get expenses
    expenses = list(expense_collection.find(filter_query).sort("date", -1))
    
    # Get categories for expense data
    category_collection = get_category_collection()
    categories = {str(cat["_id"]): cat["name"] for cat in category_collection.find()}
    
    # Format expenses
    formatted_expenses = []
    for expense in expenses:
        formatted_expenses.append({
            "id": str(expense["_id"]),
            "amount": expense["amount"],
            "description": expense["description"],
            "category_id": expense["category_id"],
            "category_name": categories.get(expense["category_id"], "Unknown"),
            "date": expense["date"].isoformat(),
            "created_at": expense["created_at"].isoformat()
        })
    
    return formatted_expenses

@app.post("/api/expenses")
async def create_expense(expense_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Check if category exists
    category = category_collection.find_one({"_id": expense_data["category_id"]})
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Create expense
    expense_id = str(uuid.uuid4())
    new_expense = {
        "_id": expense_id,
        "amount": float(expense_data["amount"]),
        "description": expense_data["description"],
        "category_id": expense_data["category_id"],
        "date": datetime.fromisoformat(expense_data["date"]),
        "user_id": current_user["id"],
        "created_at": datetime.utcnow()
    }
    
    expense_collection.insert_one(new_expense)
    
    # Get category name
    category_name = category["name"]
    
    return {
        "id": expense_id,
        "amount": new_expense["amount"],
        "description": new_expense["description"],
        "category_id": new_expense["category_id"],
        "category_name": category_name,
        "date": new_expense["date"].isoformat(),
        "created_at": new_expense["created_at"].isoformat()
    }

@app.put("/api/expenses/{expense_id}")
async def update_expense(expense_id: str, expense_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Get expense
    expense = expense_collection.find_one({"_id": expense_id})
    if not expense:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Expense not found"
        )
    
    # Check if user owns this expense
    if expense["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this expense"
        )
    
    # Check if category exists
    category = category_collection.find_one({"_id": expense_data["category_id"]})
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Update expense
    expense_collection.update_one(
        {"_id": expense_id},
        {"$set": {
            "amount": float(expense_data["amount"]),
            "description": expense_data["description"],
            "category_id": expense_data["category_id"],
            "date": datetime.fromisoformat(expense_data["date"])
        }}
    )
    
    # Get updated expense
    updated_expense = expense_collection.find_one({"_id": expense_id})
    
    # Get category name
    category_name = category["name"]
    
    return {
        "id": str(updated_expense["_id"]),
        "amount": updated_expense["amount"],
        "description": updated_expense["description"],
        "category_id": updated_expense["category_id"],
        "category_name": category_name,
        "date": updated_expense["date"].isoformat(),
        "created_at": updated_expense["created_at"].isoformat()
    }

@app.delete("/api/expenses/{expense_id}")
async def delete_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    expense_collection = get_expense_collection()
    
    # Get expense
    expense = expense_collection.find_one({"_id": expense_id})
    if not expense:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Expense not found"
        )
    
    # Check if user owns this expense
    if expense["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to delete this expense"
        )
    
    # Delete expense
    expense_collection.delete_one({"_id": expense_id})
    
    return {"message": "Expense deleted successfully"}

# ------------------------
# Report routes
# ------------------------

@app.get("/api/reports/summary")
async def get_expense_summary(
    period: str = "month",  # day, week, month, year
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Get date range
    if start_date and end_date:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    else:
        # Default to current period
        now = datetime.utcnow()
        if period == "day":
            start = datetime(now.year, now.month, now.day)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        elif period == "week":
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day)
            end = start + timedelta(days=7) - timedelta(seconds=1)
        elif period == "year":
            start = datetime(now.year, 1, 1)
            end = datetime(now.year, 12, 31, 23, 59, 59)
        else:  # month
            start = datetime(now.year, now.month, 1)
            if now.month == 12:
                end = datetime(now.year + 1, 1, 1) - timedelta(seconds=1)
            else:
                end = datetime(now.year, now.month + 1, 1) - timedelta(seconds=1)
    
    # Get expenses for period
    expenses = list(expense_collection.find({
        "user_id": current_user["id"],
        "date": {"$gte": start, "$lte": end}
    }))
    
    # Get categories
    categories = {str(cat["_id"]): cat["name"] for cat in category_collection.find()}
    
    # Calculate summary by category
    category_summary = {}
    for expense in expenses:
        category_id = expense["category_id"]
        if category_id not in category_summary:
            category_summary[category_id] = {
                "category_id": category_id,
                "category_name": categories.get(category_id, "Unknown"),
                "total": 0,
                "count": 0
            }
        
        category_summary[category_id]["total"] += expense["amount"]
        category_summary[category_id]["count"] += 1
    
    # Calculate total expenses
    total_expenses = sum(category["total"] for category in category_summary.values())
    
    # Sort categories by total amount (descending)
    sorted_categories = sorted(
        category_summary.values(),
        key=lambda x: x["total"],
        reverse=True
    )
    
    return {
        "period": period,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "total_expenses": total_expenses,
        "categories": sorted_categories
    }

@app.get("/api/reports/trends")
async def get_expense_trends(
    period: str = "month",  # day, week, month, year
    months: int = 12,  # Number of months to analyze
    current_user: dict = Depends(get_current_user)
):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Get categories
    categories = {str(cat["_id"]): cat["name"] for cat in category_collection.find()}
    
    # Calculate date range
    end_date = datetime.utcnow()
    if period == "month":
        start_date = end_date - timedelta(days=30 * months)
    elif period == "year":
        start_date = datetime(end_date.year - months, end_date.month, 1)
    else:  # week or day
        start_date = end_date - timedelta(weeks=months * 4)
    
    # Get expenses
    expenses = list(expense_collection.find({
        "user_id": current_user["id"],
        "date": {"$gte": start_date, "$lte": end_date}
    }))
    
    # Convert to pandas DataFrame for analysis
    expense_data = []
    for expense in expenses:
        expense_data.append({
            "amount": expense["amount"],
            "date": expense["date"],
            "category_id": expense["category_id"],
            "category_name": categories.get(expense["category_id"], "Unknown")
        })
    
    if not expense_data:
        return {
            "message": "No expense data available for trend analysis",
            "trends": [],
            "increasing_categories": [],
            "decreasing_categories": []
        }
    
    df = pd.DataFrame(expense_data)
    
    # Set time periods for grouping
    if period == "day":
        df["period"] = df["date"].dt.strftime("%Y-%m-%d")
    elif period == "week":
        df["period"] = df["date"].dt.strftime("%Y-%U")
    elif period == "month":
        df["period"] = df["date"].dt.strftime("%Y-%m")
    else:  # year
        df["period"] = df["date"].dt.year
    
    # Calculate total expenses by period
    period_totals = df.groupby("period")["amount"].sum().reset_index()
    period_totals = period_totals.sort_values("period")
    
    # Calculate expenses by category and period
    category_period_totals = df.groupby(["category_name", "period"])["amount"].sum().reset_index()
    
    # Identify increasing/decreasing trends
    trend_results = []
    
    # Need at least 3 periods for meaningful trend analysis
    if len(period_totals) >= 3:
        # Analyze overall trend
        overall_trend = "stable"
        last_periods = period_totals.tail(3)
        
        if last_periods.iloc[0]["amount"] < last_periods.iloc[1]["amount"] < last_periods.iloc[2]["amount"]:
            overall_trend = "increasing"
        elif last_periods.iloc[0]["amount"] > last_periods.iloc[1]["amount"] > last_periods.iloc[2]["amount"]:
            overall_trend = "decreasing"
        
        # Add overall trend
        trend_results.append({
            "type": "overall",
            "trend": overall_trend,
            "message": f"Your overall expenses are {overall_trend}"
        })
        
        # Analyze category trends
        category_trends = {}
        for category in df["category_name"].unique():
            cat_data = category_period_totals[category_period_totals["category_name"] == category]
            
            if len(cat_data) >= 3:
                sorted_cat_data = cat_data.sort_values("period")
                last_cat_periods = sorted_cat_data.tail(3)
                
                if len(last_cat_periods) == 3:
                    cat_trend = "stable"
                    if last_cat_periods.iloc[0]["amount"] < last_cat_periods.iloc[1]["amount"] < last_cat_periods.iloc[2]["amount"]:
                        cat_trend = "increasing"
                    elif last_cat_periods.iloc[0]["amount"] > last_cat_periods.iloc[1]["amount"] > last_cat_periods.iloc[2]["amount"]:
                        cat_trend = "decreasing"
                    
                    category_trends[category] = cat_trend
        
        # Find categories with significant trends
        increasing_categories = [cat for cat, trend in category_trends.items() if trend == "increasing"]
        decreasing_categories = [cat for cat, trend in category_trends.items() if trend == "decreasing"]
        
        # Add category trend messages
        if increasing_categories:
            trend_results.append({
                "type": "category_increase",
                "categories": increasing_categories,
                "message": f"Your spending in {', '.join(increasing_categories)} is increasing"
            })
        
        if decreasing_categories:
            trend_results.append({
                "type": "category_decrease",
                "categories": decreasing_categories,
                "message": f"Your spending in {', '.join(decreasing_categories)} is decreasing"
            })
    
    # Format trend data for plotting (periods and values)
    trend_data = {
        "periods": period_totals["period"].tolist(),
        "values": period_totals["amount"].tolist()
    }
    
    # Format category data for plotting
    category_data = {}
    for category in df["category_name"].unique():
        cat_data = category_period_totals[category_period_totals["category_name"] == category]
        cat_data = cat_data.sort_values("period")
        
        # Get all periods for consistent x-axis
        all_periods = period_totals["period"].tolist()
        cat_values = []
        
        # Fill in missing periods with 0
        for period in all_periods:
            period_value = cat_data[cat_data["period"] == period]["amount"].values
            if len(period_value) > 0:
                cat_values.append(float(period_value[0]))
            else:
                cat_values.append(0)
        
        category_data[category] = cat_values
    
    return {
        "trend_data": trend_data,
        "category_data": category_data,
        "trends": trend_results,
        "increasing_categories": [cat for cat, trend in category_trends.items() if trend == "increasing"] if "category_trends" in locals() else [],
        "decreasing_categories": [cat for cat, trend in category_trends.items() if trend == "decreasing"] if "category_trends" in locals() else []
    }

@app.get("/api/reports/export-pdf")
async def export_pdf_report(
    period: str = "month",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Get date range
    if start_date and end_date:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    else:
        # Default to current period
        now = datetime.utcnow()
        if period == "day":
            start = datetime(now.year, now.month, now.day)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        elif period == "week":
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day)
            end = start + timedelta(days=7) - timedelta(seconds=1)
        elif period == "year":
            start = datetime(now.year, 1, 1)
            end = datetime(now.year, 12, 31, 23, 59, 59)
        else:  # month
            start = datetime(now.year, now.month, 1)
            if now.month == 12:
                end = datetime(now.year + 1, 1, 1) - timedelta(seconds=1)
            else:
                end = datetime(now.year, now.month + 1, 1) - timedelta(seconds=1)
    
    # Get expenses for period
    expenses = list(expense_collection.find({
        "user_id": current_user["id"],
        "date": {"$gte": start, "$lte": end}
    }).sort("date", -1))
    
    # Get categories
    categories = {str(cat["_id"]): cat["name"] for cat in category_collection.find()}
    
    # Calculate summary by category
    category_summary = {}
    for expense in expenses:
        category_id = expense["category_id"]
        if category_id not in category_summary:
            category_summary[category_id] = {
                "category_name": categories.get(category_id, "Unknown"),
                "total": 0,
                "count": 0
            }
        
        category_summary[category_id]["total"] += expense["amount"]
        category_summary[category_id]["count"] += 1
    
    # Sort categories by total amount (descending)
    sorted_categories = sorted(
        category_summary.items(),
        key=lambda x: x[1]["total"],
        reverse=True
    )
    
    # Format expenses for report
    formatted_expenses = []
    for expense in expenses:
        formatted_expenses.append({
            "date": expense["date"].strftime("%Y-%m-%d"),
            "category": categories.get(expense["category_id"], "Unknown"),
            "description": expense["description"],
            "amount": f"${expense['amount']:.2f}"
        })
    
    # Calculate total
    total_amount = sum(expense["amount"] for expense in expenses)
    
    # Create PDF file
    buffer = BytesIO()
    
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=12
    )
    
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10,
        spaceBefore=10
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    # Content elements
    elements = []
    
    # Title
    title_text = f"Expense Report: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"
    elements.append(Paragraph(title_text, title_style))
    
    # Summary section
    elements.append(Paragraph("Summary", heading_style))
    
    # Total expenses
    elements.append(Paragraph(f"Total Expenses: ${total_amount:.2f}", normal_style))
    elements.append(Paragraph(f"Number of Expenses: {len(expenses)}", normal_style))
    
    # Category summary
    elements.append(Paragraph("Expenses by Category", heading_style))
    
    category_data = [["Category", "Amount", "Count"]]
    for cat_id, summary in sorted_categories:
        category_data.append([
            summary["category_name"],
            f"${summary['total']:.2f}",
            summary["count"]
        ])
    
    category_table = Table(category_data, colWidths=[250, 100, 80])
    category_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    elements.append(category_table)
    elements.append(Spacer(1, 20))
    
    # Detailed expenses
    elements.append(Paragraph("Expense Details", heading_style))
    
    if formatted_expenses:
        expense_data = [["Date", "Category", "Description", "Amount"]]
        for expense in formatted_expenses:
            expense_data.append([
                expense["date"],
                expense["category"],
                expense["description"],
                expense["amount"]
            ])
        
        expense_table = Table(expense_data, colWidths=[80, 100, 200, 80])
        expense_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (3, 0), (3, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(expense_table)
    else:
        elements.append(Paragraph("No expenses found for this period.", normal_style))
    
    # Build PDF
    doc.build(elements)
    
    # Get the PDF content
    pdf_content = buffer.getvalue()
    buffer.close()
    
    # Return base64-encoded PDF
    encoded_pdf = base64.b64encode(pdf_content).decode('utf-8')
    
    return {
        "pdf_data": encoded_pdf,
        "filename": f"expense_report_{start.strftime('%Y%m%d')}_{end.strftime('%Y%m%d')}.pdf"
    }

@app.get("/api/reports/charts")
async def get_chart_data(
    chart_type: str = "pie",  # pie, bar, line
    period: str = "month",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    expense_collection = get_expense_collection()
    category_collection = get_category_collection()
    
    # Get date range
    if start_date and end_date:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    else:
        # Default to current period
        now = datetime.utcnow()
        if period == "day":
            start = datetime(now.year, now.month, now.day)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        elif period == "week":
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day)
            end = start + timedelta(days=7) - timedelta(seconds=1)
        elif period == "year":
            start = datetime(now.year, 1, 1)
            end = datetime(now.year, 12, 31, 23, 59, 59)
        else:  # month
            start = datetime(now.year, now.month, 1)
            if now.month == 12:
                end = datetime(now.year + 1, 1, 1) - timedelta(seconds=1)
            else:
                end = datetime(now.year, now.month + 1, 1) - timedelta(seconds=1)
    
    # Get expenses for period
    expenses = list(expense_collection.find({
        "user_id": current_user["id"],
        "date": {"$gte": start, "$lte": end}
    }))
    
    # Get categories
    categories = {str(cat["_id"]): cat["name"] for cat in category_collection.find()}
    
    if not expenses:
        return {
            "chart_type": chart_type,
            "message": "No expense data available for selected period",
            "data": {}
        }
    
    # Create DataFrame for analysis
    expense_data = []
    for expense in expenses:
        expense_data.append({
            "amount": expense["amount"],
            "date": expense["date"],
            "category_id": expense["category_id"],
            "category_name": categories.get(expense["category_id"], "Unknown")
        })
    
    df = pd.DataFrame(expense_data)
    
    if chart_type == "pie":
        # Group by category
        cat_totals = df.groupby("category_name")["amount"].sum()
        
        # Format for chart.js
        chart_data = {
            "labels": cat_totals.index.tolist(),
            "datasets": [{
                "data": cat_totals.values.tolist(),
                "backgroundColor": [
                    "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
                    "#FF9F40", "#8AC249", "#EA526F", "#25CED1", "#FCEADE"
                ],
                "hoverBackgroundColor": [
                    "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
                    "#FF9F40", "#8AC249", "#EA526F", "#25CED1", "#FCEADE"
                ]
            }]
        }
    
    elif chart_type == "bar":
        # Group by category
        cat_totals = df.groupby("category_name")["amount"].sum().sort_values(ascending=False)
        
        # Format for chart.js
        chart_data = {
            "labels": cat_totals.index.tolist(),
            "datasets": [{
                "label": "Expenses by Category",
                "data": cat_totals.values.tolist(),
                "backgroundColor": "#36A2EB",
                "borderColor": "#2693e6",
                "borderWidth": 1
            }]
        }
    
    elif chart_type == "line":
        # Group by date
        if period == "year":
            df["period"] = df["date"].dt.strftime("%Y-%m")
        elif period == "month":
            df["period"] = df["date"].dt.strftime("%Y-%m-%d")
        elif period == "week":
            df["period"] = df["date"].dt.strftime("%Y-%m-%d")
        else:  # day
            df["period"] = df["date"].dt.strftime("%H:00")
        
        date_totals = df.groupby("period")["amount"].sum()
        
        # Sort by date
        date_totals = date_totals.sort_index()
        
        # Format for chart.js
        chart_data = {
            "labels": date_totals.index.tolist(),
            "datasets": [{
                "label": "Expenses Over Time",
                "data": date_totals.values.tolist(),
                "fill": False,
                "borderColor": "#36A2EB",
                "tension": 0.1
            }]
        }
    
    return {
        "chart_type": chart_type,
        "period": period,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "data": chart_data
    }

@app.get("/")
async def root():
    return {"message": "Welcome to Expense Tracker API"}
