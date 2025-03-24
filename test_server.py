import unittest
import json
import jwt
import requests
import threading
import time
import os
from main import MyServer, HTTPServer, init_db, generate_and_store_keys, db_file

class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Make sure the database file doesn't exist when we start
        try:
            if os.path.exists(db_file):
                os.remove(db_file)
        except:
            time.sleep(1)  # Wait a bit and try again
            try:
                if os.path.exists(db_file):
                    os.remove(db_file)
            except:
                pass  # If we still can't remove it, proceed anyway

        # Start the server
        cls.server = HTTPServer(('localhost', 8080), MyServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(2)  # Give the server more time to start

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=1)

    def test_jwks_endpoint(self):
        """Test the JWKS endpoint returns valid keys"""
        response = requests.get('http://localhost:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('keys', data)
        self.assertEqual(len(data['keys']), 1)
        key = data['keys'][0]
        self.assertEqual(key['alg'], 'RS256')
        self.assertEqual(key['kty'], 'RSA')
        self.assertEqual(key['use'], 'sig')
        self.assertEqual(key['kid'], '2')

    def test_auth_endpoint_valid(self):
        """Test the auth endpoint with valid key"""
        response = requests.post('http://localhost:8080/auth', 
                               json={'username': 'testuser', 'password': 'testpass'})
        self.assertEqual(response.status_code, 200)
        token = response.content.decode('utf-8')
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn('user', decoded)
        self.assertIn('exp', decoded)

    def test_auth_endpoint_expired(self):
        """Test the auth endpoint with expired key"""
        response = requests.post('http://localhost:8080/auth?expired=true',
                               json={'username': 'testuser', 'password': 'testpass'})
        self.assertEqual(response.status_code, 200)
        token = response.content.decode('utf-8')
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn('user', decoded)
        self.assertIn('exp', decoded)

    def test_method_not_allowed(self):
        """Test that incorrect HTTP methods return 405"""
        endpoints = ['/.well-known/jwks.json', '/auth']
        methods = ['PUT', 'DELETE', 'PATCH', 'HEAD']
        for endpoint in endpoints:
            for method in methods:
                response = requests.request(method, f'http://localhost:8080{endpoint}')
                self.assertEqual(response.status_code, 405)

    def test_invalid_endpoint(self):
        """Test that invalid endpoints return 405"""
        response = requests.get('http://localhost:8080/invalid')
        self.assertEqual(response.status_code, 405)

if __name__ == '__main__':
    unittest.main() 