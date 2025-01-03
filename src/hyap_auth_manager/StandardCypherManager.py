import os
import subprocess
import time
from datetime import timedelta
import jwt

class StandardCypherManager():
    def __init__(self, algorithm: str="RS256", output_dir: str="./keys"):
        """
        Define standard cypher manager.

        Args:
            algorithm (str): Asymmetrics algorithm to do cryptography.
            output_dir (str): The directory to save the keys (default is "./keys").

        Supported algorithms:
        Algorithm |	Type                    | Key Type      	 | Hash Function
        ----------|-------------------------|--------------------|---------------
        RS256     | RSA (Asymmetric)	    | Public/Private Key | SHA-256
        RS384     | RSA (Asymmetric)	    | Public/Private Key | SHA-384
        RS512     | RSA (Asymmetric)	    | Public/Private Key | SHA-512
        ES256     | ECDSA (Asymmetric)	    | Public/Private Key | SHA-256
        ES384     | ECDSA (Asymmetric)	    | Public/Private Key | SHA-384
        ES512     | ECDSA (Asymmetric)	    | Public/Private Key | SHA-512
        PS256     | RSASSA-PSS (Asymmetric) | Public/Private Key | SHA-256
        PS384     | RSASSA-PSS (Asymmetric) | Public/Private Key | SHA-384
        PS512     | RSASSA-PSS (Asymmetric) | Public/Private Key | SHA-512
        """
        self.crypto_algorithm = algorithm
        self.output_dir = output_dir
        self.private_key_name = "private.key"
        self.public_key_name = "public.key"

    def generate_keys(self, bit_size: int=2048):
        """
        Generate RSA private and public keys.

        Args:
            bit_size (int): The size of the key to generate (default is 2048).

        Return: keys path (dict)
        """
        try:
            # Setting up path for keys directory
            os.makedirs(self.output_dir, exist_ok=True)
            private_key_path = os.path.join(self.output_dir, self.private_key_name)
            public_key_path = os.path.join(self.output_dir, self.public_key_name)

            # Generate private key and public key
            subprocess.run(["openssl", "genrsa", "-out", private_key_path, str(bit_size)])
            subprocess.run(["openssl", "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path])

            return {
                "private_key_path": private_key_path,
                "public_key_path": public_key_path
            }
        except Exception as e:
            raise Exception(f"Failed to generate keys: {e}")
        
    def read_keys(self, key_type : str):
        """
        Read asymmetrics key file private.key or public.key.

        Args:
            key_type (str): The type of key to read ("PRIVATE" or "PUBLIC"). Default is None. 

        Return: str
        """
        key_path_dictionary = {
            "PRIVATE": os.path.join(self.output_dir, self.private_key_name),
            "PUBLIC": os.path.join(self.output_dir, self.public_key_name)
        }

        try:
            key_path = key_path_dictionary[key_type]
            with open(key_path, "r") as key_file:
                KEY_VALUE = key_file.read()
            return KEY_VALUE
        except Exception as e:
            raise Exception(f"Failed to read key: {e}")
        
    def encode_data(self, PRIVATE_KEY: str, data: dict, expires_delta: int=0):
        """
        Encode Data to keep the security of secret informations.

        Args:
            PRIVATE_KEY (str): String value of private.key. Could be loaded with class function read_keys("PRIVATE") function.
            data (dict): Data that will be encoded.
            expires_delta (int): expires value in minutes. Default to 0 minutes. Set to 0 to deny expiration time.
        
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
                PRIVATE_KEY,
                algorithm=self.crypto_algorithm
            )
            return {
                "encoded_data": f"{encoded_data_jwt}"
            }
        except Exception as e:
            raise Exception(f"Failed to create access token: {e}")
        
    def decode_data(self, PUBLIC_KEY: str, token: str):
        """
        Check the information of encoded data.

        Args:
            PUBLIC_KEY (str): String value of public.key. Could be loaded with class function read_keys("PUBLIC") function.
            data (dict): Data that will be encoded.
            expires_delta (int): expires value in minutes. Default to 15 minutes. Set to 0 to deny expiration time.
        
        Return:
        """
        try:
            data = jwt.decode(token, PUBLIC_KEY, algorithms=self.crypto_algorithm)
            return data
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"error": "Token invalid"}
        