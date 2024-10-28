from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
#sets hostname and server port
hostName = "localhost"
serverPort = 8080

# path for the database file
db_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "totally_not_my_privateKeys.db")

# Check if the db file exists and create if missing
if not os.path.isfile(db_file_path):
    with open(db_file_path, 'w') as db_file:
        pass

# Initialize database
def initialize_database(db_file):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")

# Save key 
def save_key(db_file, key_pem, expiration):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expiration))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error saving key to database: {e}")


# Fetch keys
def fetch_key(db_file, expired=False):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            condition = "<=" if expired else ">"
            cursor.execute("SELECT kid, key FROM keys WHERE exp " + condition + " ?", (int(datetime.datetime.now().timestamp()),))
            result = cursor.fetchone()
            return result if result else (None, None)
    except sqlite3.Error as e:
        print(f"Error fetching key from database: {e}")
        return (None, None)

# Ensure initialization before server starts
initialize_database(db_file_path)

# Generate private keys rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Convert private key to pem
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Save the keys to the database
save_key(db_file_path, pem, int((datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()))  # Active key

# Helper function to convert int to base64
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')  
    return encoded.decode('utf-8')


def get_keys(db_file):  # get keys that are not expired
    connect = sqlite3.connect(db_file)
    cursor = connect.cursor()
    cursor.execute("SELECT key FROM keys WHERE exp > ?;", (int(datetime.datetime.utcnow().timestamp()),))
    keys = cursor.fetchall()
    connect.close()
    #Return key data as bytes
    return [key_row[0] if isinstance(key_row[0], bytes) else key_row[0].encode() for key_row in keys] 

#MyServer class
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            vkeys = get_keys(db_file_path)
            jwks_keys = []
            for key_data in vkeys:
                # Ensure key_data is in bytes
                try:
                    # Check if key_data is in bytes
                    if isinstance(key_data, bytes): 
                        pkey = serialization.load_pem_private_key(key_data, password=None)
                        numbers = pkey.private_numbers()
                        jwks_keys.append({
                            "alg": "RS256",
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "goodKID",
                            "n": int_to_base64(numbers.public_numbers.n),
                            "e": int_to_base64(numbers.public_numbers.e),
                        })
                    else:
                        print("Key data is not in bytes:", type(key_data))
                except Exception as e:
                    print(f"Error processing key data: {e}")
            keys = {
                "keys": jwks_keys
            }
                
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server running on {hostName}:{serverPort}...")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    #ChatGPT Prompts:
    #How do I handle any errors in the initialize database, save key, and key functions
    #How do i fix " cannot return the address of a unicode object" error that I'm getting for key data
    #Debug statements to ensure that my key data is in bytes not strings in get_keys and POST functions