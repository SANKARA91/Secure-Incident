from fastapi import APIRouter, HTTPException
from app.core.security import create_access_token
from app.db.schemas import UserCreate

router = APIRouter()

@router.post("/login")
def login(user: UserCreate):
    # Simple static login for now
    if user.username == "admin" and user.password == "admin":
        token = create_access_token({"sub": user.username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")
