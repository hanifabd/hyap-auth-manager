# OPTIONAL: REMOVE THIS ---------------------------------------------------------------------------------
import sys
import os

# Add the directory containing AsymmetricsKeysManager.py to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
# -------------------------------------------------------------------------------------------------------

from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from hyap_auth_manager.AsymmetricsKeysManager import AsymmetricsKeysManager

app = FastAPI()

# Models
class TokenData(BaseModel):
    username: str

class User(BaseModel):
    username: str
    password: str

# Fake database for user credentials
fake_users_db = {
    "bambang1": {"username": "bambang1", "password": "bambangpass1"},
}

# Helper Functions
key_manager = AsymmetricsKeysManager(algorithm="RS256", output_dir="../tests/keys")
private_key_val = key_manager.read_keys("PRIVATE")
public_key_val = key_manager.read_keys("PUBLIC")

# Routes
@app.post("/login")
def login(user: User):
    # Check user and password
    user_data = fake_users_db.get(user.username)
    if not user_data or user_data["password"] != user.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # Create a JWT token with the username as the payload
    token = key_manager.generate_access_token(PRIVATE_KEY=private_key_val, data={"username": user.username}, expires_delta=15)
    return {"access_token": token}

# Token authentication function
def token_authenticator(
    authorization: str = Header(...),  # Extract Authorization header
    public_key: str = Depends(lambda: public_key_val), 
    auth_service: AsymmetricsKeysManager = Depends()
) -> dict:
    # Extract the token from the Authorization header
    token = authorization.split(" ")[1]  # Bearer token extraction
    
    # Check if the token is valid using the public key
    result = auth_service.check_access_token(PUBLIC_KEY=public_key, token=token)
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
    print(token)
    return {"message": "Access granted", "user": token.get("data").get("username")}

# To run the app, use the command:
# uvicorn test-api-asymmetrics:app --reload

# Login
# curl -X POST "http://127.0.0.1:8000/login" -H 'accept: application/json' -H "Content-Type: application/json" -d '{"username":"bambang1","password":"bambangpass1"}'

# Access protected
# curl -X 'GET' 'http://127.0.0.1:8000/protected' -H 'accept: application/json'  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoiYmFtYmFuZzEifSwiZXhwIjoxNzM1MTAxMTQwLjMyMDgyNjN9.cUhhJyb_z8mN6NXf8MuMjM-C2HGROObbrmQHuc15mA642jpZmVy1IM2nrH2aybnkZ0VHW3KiSOjK-Ol2K48vs_M7ixgNOZI_HyEDnq7pkH7jKRk_1L_AKU-loo9YSrdskUyX--W-sQ6f_1dyJuyq64abw67MPfErkFsOHL5aXYBJDL5GU4VU_pMFmIG1tAsqndbLY_egBgicYBSV3o48H7KLCg93kaftj5QDulWkCpLMuH2r0gQhjKoZF8WNkVvod3amYdgRALZaaF1H_LunSZSuwUCvQJF-0B9jkLPDeyeGwWDsBvWGEfxQxqf1CdRqhhUmUAo76SSNxTLktz1Z3A'
