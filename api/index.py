import json
import base64
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests
import os
import random

app = Flask(__name__)

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def aes_decryption(cipher_hex):
    key_hex = "0a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef"
    iv_hex = "3d8b0c3e68a0f1b4d9e1a0c5b3c1e8f7"

    key = hex_to_bytes(key_hex)
    iv = hex_to_bytes(iv_hex)
    cipher_bytes = hex_to_bytes(cipher_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
    return plaintext_bytes.decode('utf-8')

@app.route('/api/provision', methods=['POST'])
def provision_account():
    data = request.get_json()
    ziv_endpoint = data.get('zivEndPoint')
    username = data.get('userName', None)

    headers = {
        "Authorization": "Bearer zi_zi_zi",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 4 Build/RQ3A.210805.001.A1)"
    }

    payload = {}
    if username:
        payload['username'] = username

    url = f"https://{ziv_endpoint}:3000/grantAccess"
    response = requests.post(url, headers=headers, json=payload)
    server_response = response.json()

    user_name = server_response['username']
    decrypted_password = aes_decryption(server_response['password'])
    expiration_date = server_response['expirationDate']

    return jsonify({
        "username": user_name,
        "password": decrypted_password,
        "expirationDate": expiration_date
    })



@app.route('/')
def home():
    return 'Hello, World!'

@app.route('/about')
def about():
    return 'About'

