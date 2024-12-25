import sys
import os

# Add the directory containing AsymmetricsKeysManager.py to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import json
from hyap_auth_manager.AsymmetricsKeysManager import AsymmetricsKeysManager

# Initialize RSA Manager
key_manager = AsymmetricsKeysManager(algorithm="RS256", output_dir="../tests/keys")

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