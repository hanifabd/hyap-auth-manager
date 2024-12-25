# OPTIONAL: REMOVE THIS ---------------------------------------------------------------------------------
import sys
import os

# Add the directory containing AsymmetricsKeysManager.py to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
# -------------------------------------------------------------------------------------------------------

from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from hyap_auth_manager.SymmetricsKeysManager import SymmetricsKeysManager

app = FastAPI()

# Models
class TokenData(BaseModel):
    username: str

class User(BaseModel):
    username: str
    password: str

fake_users_db = {
    "bambang1": {"username": "bambang1", "password": "bambangpass1"},
}

# Helper Functions
key_manager = SymmetricsKeysManager(secret_key="example-secret-keys-here")

# Routes
@app.post("/login")
def login(user: User):
    # Check user and password
    print(fake_users_db.get(user.username))
    user_data = fake_users_db.get(user.username)
    if not user_data or user_data["password"] != user.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # Create a JWT token with the username as the payload
    token = key_manager.generate_access_token(data={"username": user.username}, expires_delta=15)
    return {"access_token": token, "token_type": "bearer"}

# Override key_manager check access token function
def token_authenticator(authorization: str = Header(None)) -> dict:
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.split("Bearer ")[-1]
    
    result = key_manager.check_access_token(token)
    if "error" in result:
        # Raise HTTPException if there is an error in the token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result["error"],
            headers={"WWW-Authenticate": "Bearer"},
        )
    return result

@app.get("/protected")
def protected_route(token: dict = Depends(token_authenticator)):
    # If token is valid, return the protected message
    return {"message": "Access granted", "user": token.get("data").get("username")}

# To run the app, use the command:
# uvicorn test-api-symmetrics:app --reload

# Login
# curl -X POST "http://127.0.0.1:8000/login" -H "Content-Type: application/json" -d '{"username":"bambang1","password":"bambangpass1"}'

# Access protected
# curl -X GET "http://127.0.0.1:8000/protected" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoiYmFtYmFuZzEifSwiZXhwIjoxNzM1MTAxMzc4LjgwMDc3OTZ9.9RmXuO4znxz7W1fA3k3mykn_57RoTAbrDTODRKqG32U"