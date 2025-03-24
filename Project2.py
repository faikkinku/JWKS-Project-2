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

hostName = "localhost"
serverPort = 8080
db_file = "totally_not_my_privateKeys.db"


def init_db():
    """Initialize the SQLite database and create the keys table if it doesn't exist."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def generate_and_store_keys(conn):
    """Generate and store RSA keys in the database."""
    cursor = conn.cursor()

    # Check if keys already exist
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    if count >= 2:  # We already have both keys
        return

    # Generate expired key
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Set expired time to a guaranteed expired timestamp (24 hours ago)
    expired_time = int((datetime.datetime.utcnow() - datetime.timedelta(hours=24)).timestamp())

    # Generate valid key
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Set valid time to 24 hours in the future to ensure it's valid
    valid_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=24)).timestamp())

    # Store expired key first
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, expired_time))
    # Store valid key second
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, valid_time))
    conn.commit()


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            current_time = int(datetime.datetime.utcnow().timestamp())

            if 'expired' in params:
                # Look for expired keys (less than or equal to current time)
                cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1", (current_time,))
                row = cursor.fetchone()
                if row is None:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"No expired key found")
                    return
                kid, key_pem = row
                token_exp = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                # Look for valid keys (greater than current time)
                cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (current_time,))
                row = cursor.fetchone()
                if row is None:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"No valid key found")
                    return
                kid, key_pem = row
                token_exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            conn.close()

            try:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                headers = {
                    "kid": str(kid)
                }
                token_payload = {
                    "user": "username",
                    "exp": token_exp
                }

                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            rows = cursor.fetchall()
            conn.close()

            keys = {
                "keys": []
            }

            for row in rows:
                kid, key_pem = row
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                public_numbers = private_key.public_key().public_numbers()

                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # Initialize database and generate keys
    conn = init_db()
    generate_and_store_keys(conn)
    conn.close()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server running at http://{hostName}:{serverPort}/")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
