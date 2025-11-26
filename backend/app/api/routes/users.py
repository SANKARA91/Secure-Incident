# -*- coding: utf-8 -*-
from fastapi import APIRouter
from typing import List

router = APIRouter(prefix="/users", tags=["Users"])

fake_users = [
    {"id": 1, "username": "admin", "is_admin": True},
    {"id": 2, "username": "user", "is_admin": False},
]

@router.get("/")
def get_users():
    """Récupérer la liste des utilisateurs"""
    return {"users": fake_users}

@router.get("/{user_id}")
def get_user(user_id: int):
    """Récupérer un utilisateur spécifique"""
    user = next((u for u in fake_users if u["id"] == user_id), None)
    if not user:
        return {"error": "User not found"}
    return user