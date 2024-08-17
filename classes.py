import binascii
import codecs
import hashlib
import pickle

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from flask import Flask, request, after_this_request


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


class AesEncrypter:

    def __init__(self):
        self.key = b'javajavajavajava'

    def encrypt(self, decrypt_data_str):
        cipher = AES.new(self.key, AES.MODE_CBC, 'init_val_is_16by'.encode('utf8'))
        padded_data = pad(bytes(decrypt_data_str, 'utf8'), AES.block_size)
        encrypt_data = cipher.encrypt(padded_data)
        encrypt_data_str = binascii.hexlify(encrypt_data).decode()
        return encrypt_data_str

    def decrypt(self, encrypt_data_str):
        encrypt_data = binascii.unhexlify(encrypt_data_str)
        cipher = AES.new(self.key, AES.MODE_CBC, 'init_val_is_16by'.encode('utf8'))
        decrypt_data = cipher.decrypt(encrypt_data)
        un_padded_data = unpad(decrypt_data, AES.block_size)
        decrypt_data_str = str(un_padded_data, 'utf8')
        return decrypt_data_str

class AuthService:
    def __init__(self, storage, aes_encrypter):
        self.storage = storage
        self.aes_encrypter = aes_encrypter

    def login(self, username, password):
        if self.storage.login(username, password):
            user = self.storage.find_user(username)
            dump = pickle.dumps(user)
            user_str = codecs.encode(dump, 'base64').decode()
            return self.aes_encrypter.encrypt(user_str)
        else:
            return ''

    def registration(self, username, password):
        if not self.storage.has_username(username):
            self.storage.registration(username, password)
        else:
            raise Exception('username is busy')

    def is_auth(self, session_id):
        user_str = self.aes_encrypter.decrypt(session_id)
        load = codecs.decode(user_str.encode(), 'base64')
        user_from_session_id = pickle.loads(load)
        if self.storage.find_user(user_from_session_id.username):
            user_from_storage = self.storage.find_user(user_from_session_id.username)
            if user_from_session_id.psw_hash == user_from_storage.psw_hash:
                return user_from_storage
            else:
                return None
        else:
            return None


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
        session_id = auth_service.login(username, password)

        @after_this_request
        def set_cookie(response):
            response.set_cookie('session_id', str(session_id), max_age=10000)
            return response

        return 'ok'

    @app.route('/logout', methods=['GET'])
    def logout():

        @after_this_request
        def clear_cookie(response):
            response.delete_cookie('session_id')
            return response

        return 'logout ok'

    @app.route('/load', methods=['GET'])
    def load():
        if 'session_id' in request.cookies:
            session_id = request.cookies['session_id']
            user = auth_service.is_auth(session_id)
            if user is None:
                raise Exception('not auth1')
            else:
                return 'success, your role: ' + user.role
        else:
            raise Exception('not auth2')

    @app.route('/gen-api-key', methods=['POST'])
    def gen_api_key():
        if 'session_id' in request.cookies:
            session_id = request.cookies['session_id']
            user = auth_service.is_auth(session_id)
            if user is None:
                raise Exception('not auth1')
            else:
                r = request.json
                password = r['password']
                return auth_service.login(user.username, password)
        else:
            raise Exception('not auth2')

    @app.route('/load-on-api-key', methods=['POST'])
    def load_on_api_key():
        r = request.json
        if 'api-key' in r:
            api_key = r['api-key']
            user = auth_service.is_auth(api_key)
            if user is None:
                raise Exception('not auth1')
            else:
                return 'api key info: ' + str(user.psw_hash)
        else:
            raise Exception('not auth2')

    @app.route('/get-data-on-api-key', methods=['POST'])
    def get_data_on_api_key():
        r = request.json
        if 'api-key' in r:
            api_key = r['api-key']
            data = {'api-key': api_key}
            headers = {'Content-type': 'application/json'}
            response = requests.post('http://localhost:8082/load-on-api-key', json=data, headers=headers)
            return response.content
        else:
            raise Exception('not api-key')

    return app