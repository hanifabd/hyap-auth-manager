# **HYAP Auth Manager: Python Authentication Framework for Asymmetrics and Symmetrics Keys**

<p align="center">
  <picture>
    <img alt="banner" src="./assets/banner.jpg" width=100%>
  </picture>
</p>

## **About**
HYAP Authentication Manager is a lightweight library designed to simplify the generation and verification of JWT (JSON Web Tokens) in your applications. It provides easy-to-use methods for securely creating tokens and validating them, ensuring that authentication processes are smooth and secure.

## **Requirements**
- Python 3.7 or Higher
- cryptography
- pyjwt

## **Key Features**

- **JWT Generation**: Securely create JWT tokens with customizable payloads.
- **JWT Validation**: Easily verify the authenticity of JWT tokens, ensuring that they haven't been tampered with.
- **Token Expiration**: Set custom expiration times for tokens to ensure they are valid for a specific duration.
- **Asymmetrics and Symmetrics Support**: Supports both symmetric (HMAC) and asymmetric (RSA) signing algorithms for token generation and validation.

|Algorithm|Type|Key Type|Hash Function|
|---|---|---|---|
|HS256|HMAC (Symmetric)|Secret Key|SHA-256|
|RS256|RSA (Asymmetric)|Public/Private Key|SHA-256|
|RS384|RSA (Asymmetric)|Public/Private Key|SHA-384|
|RS512|RSA (Asymmetric)|Public/Private Key|SHA-512|
|ES256|ECDSA (Asymmetric)|Public/Private Key|SHA-256|
|ES384|ECDSA (Asymmetric)|Public/Private Key|SHA-384|
|ES512|ECDSA (Asymmetric)|Public/Private Key|SHA-512|
|PS256|RSASSA-PSS (Asymmetric)|Public/Private Key|SHA-256|
|PS384|RSASSA-PSS (Asymmetric)|Public/Private Key|SHA-384|
|PS512|RSASSA-PSS (Asymmetric)|Public/Private Key|SHA-512|

## Usage
### Manual Installation via Github
1. Clone Repository
    ```
    git clone https://github.com/hanifabd/hyap-auth-manager
    ```
2. Installation
    ```
    cd hyap-auth-manager && pip install .
    ```
### Installation Using Pip
1. Installation
    ```sh
    pip install hyap-auth-manager
    ```

### **Asymmetrics Key Usage | [Example Keys](./tests/keys/) | [Fastapi Example](./tests/test-api-asymmetrics.py)**
**Standar Usage Example**
```py
import json
from hyap_auth_manager.AsymmetricsKeysManager import AsymmetricsKeysManager

# Initialize Asymmetrics Manager
key_manager = AsymmetricsKeysManager(algorithm="RS256", output_dir="./keys")

# Generate Keys (Private and Public)
path = key_manager.generate_keys()
print(json.dumps(path, indent=2))

# Read Keys
private_key_val = key_manager.read_keys("PRIVATE")
public_key_val = key_manager.read_keys("PUBLIC")
print(private_key_val)
print(public_key_val)

# Create Access Token
access_token = key_manager.generate_access_token(
    PRIVATE_KEY=private_key_val, 
    data={"username": "bambang"},
    expires_delta=30, # in minutes
)
print(json.dumps(access_token, indent=2))

# Check Access Token
token_status = key_manager.check_access_token(
    PUBLIC_KEY=public_key_val,
    token=access_token.get("token").split("Bearer ")[1]
)
print()
print(token_status)
```
**Fastapi Example**
```py
# Fastapi Example
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
```

---

### **Symmetrics Key Usage | [Fastapi Example](./tests/test-api-symmetrics.py)**
**Standar Usage Example**
```py
import json
from hyap_auth_manager.SymmetricsKeysManager import SymmetricsKeysManager

# Initialize Symmetrics Manager
key_manager = SymmetricsKeysManager(secret_key="example-secret-keys-here")

# Create Access Token
access_token = key_manager.generate_access_token(
    data={"username": "bambang"},
    expires_delta=0, # in minutes
)
print(json.dumps(access_token, indent=2))

# Check Access Token
token_status = key_manager.check_access_token(
    token=access_token.get("token").split("Bearer ")[1]
)
print()
print(token_status)
```
**Fastapi Example**
```py
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
```