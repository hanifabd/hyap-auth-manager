import sys
import os

# Add the directory containing SymmetricsKeysManager.py to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import json
from hyap_auth_manager.SymmetricsKeysManager import SymmetricsKeysManager

# Initialize RSA Manager
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