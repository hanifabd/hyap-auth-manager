import time
from datetime import timedelta
import jwt

class SymmetricsKeysManager():
    def __init__(self, secret_key: str):
        self.crypto_algorithm = "HS256"
        self.secret_key = secret_key
        
    def generate_access_token(self, data: dict, expires_delta: int=15):
        """
        Create jwt access token with expiration time, Default to 15 minutes.

        Args:
            data (dict): Data that will be encoded.
            expires_delta (int): expires value in minutes. Default to 15 minutes. Set to 0 to deny expiration time.
        
        Return: generated token (dict)
        """
        try:
            data_to_encode = {
                "data": data,
            }

            if expires_delta != 0:
                data_to_encode.update({
                    "exp": time.time() + timedelta(minutes=expires_delta).total_seconds()
                })

            encoded_data_jwt = jwt.encode(
                data_to_encode,
                self.secret_key,
                algorithm=self.crypto_algorithm
            )
            return {
                "token_type": "bearer",
                "token": f"Bearer {encoded_data_jwt}"
            }
        except Exception as e:
            raise Exception(f"Failed to create access token: {e}")
        
    def check_access_token(self, token: str):
        """
        Check jwt access token validity.

        Args:
            data (dict): Data that will be encoded.
            expires_delta (int): expires value in minutes. Default to 15 minutes. Set to 0 to deny expiration time.
        
        Return:
        """
        try:
            data = jwt.decode(token, self.secret_key, algorithms=self.crypto_algorithm)
            return data
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"error": "Token invalid"}
        