import binascii
import codecs
import hashlib
import pickle
from datetime import datetime, timedelta

import jwt

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from flask import Flask, request, after_this_request, jsonify


class User:
    def __init__(self, username, psw_hash, role):
        self.username = username
        self.psw_hash = psw_hash
        self.role = role


class Storage:
    store = {
        'user': User('user', hashlib.md5(b'user').digest(), 'user'),
        'admin': User('admin', hashlib.md5(b'admin').digest(), 'admin'),
        'moder': User('moder', hashlib.md5(b'moder').digest(), 'moder')
    }

    def login(self, username, password):
        psw_hash = hashlib.md5(bytes(password, 'utf-8')).digest()
        return username in self.store and psw_hash == self.store[username].psw_hash

    def registration(self, username, password):
        psw_hash = hashlib.md5(bytes(password, 'utf-8')).digest()
        self.store[username] = User(username, psw_hash, 'user')

    def has_username(self, username):
        return username in self.store

    def find_user(self, username):
        if username in self.store:
            return self.store[username]
        else:
            raise Exception('not check')

class JwtEmitter:
    def __init__(self):
        self.key = 'secret_key'
        self.alg = 'HS256'

    def emit(self, username, role, is_access):
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + timedelta(minutes=1 if is_access else 60),
            'subject': username,
            'role': role
        }
        return jwt.encode(payload, self.key, algorithm=self.alg)

    def validate(self, token):
        payload = jwt.decode(token, self.key, algorithms=[self.alg], options={'verify_exp': True})
        return payload


class AuthService:
    def __init__(self, storage, jwt_emitter):
        self.storage = storage
        self.jwt_emitter = jwt_emitter

    def login(self, username, password):
        if self.storage.login(username, password):
            user = self.storage.find_user(username)
            return self.gen_tokens(user.username, user.role)
        else:
            return None

    def registration(self, username, password):
        if not self.storage.has_username(username):
            self.storage.registration(username, password)
        else:
            raise Exception('username is busy')

    def gen_tokens(self, username, role):
        access_token = self.jwt_emitter.emit(username, role, True)
        refresh_token = self.jwt_emitter.emit(username, role, False)
        return access_token, refresh_token

    def validate_token(self, token):
        return self.jwt_emitter.validate(token)

def server(auth_service):
    app = Flask(__name__)

    @app.route('/registration', methods=['POST'])
    def registration():
        r = request.json
        username = r['username']
        password = r['password']
        auth_service.registration(username, password)
        return 'ok'

    @app.route('/login', methods=['POST'])
    def login():
        r = request.json
        username = r['username']
        password = r['password']
        access_token, refresh_token = auth_service.login(username, password)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token})

    @app.route('/refresh', methods=['POST'])
    def refresh():
        r = request.json
        if 'refresh_token' in r:
            refresh_token = r['refresh_token']
            payload = auth_service.validate_token(refresh_token)
            if payload is not None:
                access_token, refresh_token = auth_service.gen_tokens(payload['subject'], payload['role'])
                return jsonify({'access_token': access_token, 'refresh_token': refresh_token})
            else:
                raise Exception('not valid token')
        else:
            raise Exception('not refresh_token')


    @app.route('/load', methods=['GET'])
    def load():
        if 'Auth' in request.headers:
            auth_header = request.headers['Auth']
            if auth_header.startswith('Bearer_'):
                access_token = auth_header[len('Bearer_'):]
                payload = auth_service.validate_token(access_token)
                if payload is None:
                    raise Exception('not auth3')
                else:
                    return 'your role: ' + payload['role']
            else:
                raise Exception('not auth2')
        else:
            raise Exception('not auth1')


    return app