from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timedelta
from typing import Optional
import jwt
import os

SECRET_KEY = os.environ.get("AEGIS_SECRET_KEY", "aegis-sentinel-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


class AuthMiddleware(BaseHTTPMiddleware):
    EXCLUDED_PATHS = [
        "/api/login",
        "/api/register",
        "/",
        "/static",
        "/docs",
        "/openapi.json",
        "/redoc"
    ]
    
    def __init__(self, app):
        super().__init__(app)
        self.exempt_paths = [p.lower() for p in self.EXCLUDED_PATHS]
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.lower()
        
        if any(path.startswith(exempt) for exempt in self.exempt_paths):
            return await call_next(request)
        
        auth_header = request.headers.get("authorization", "")
        
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required", "error": "missing_token"}
            )
        
        token = auth_header.replace("Bearer ", "")
        
        try:
            payload = verify_token(token)
            request.state.user = payload
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        
        return await call_next(request)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
