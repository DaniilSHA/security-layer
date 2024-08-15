import hashlib
import pickle

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from flask import Flask, request, after_this_request


class User:
    def __init__(self, username, psw_hash, role):
        self.username = username
        self.psw_hash = psw_hash
        self.role = role


class Storage:
    store = {
        "user": User("user", hashlib.md5(b"user").digest(), "user"),
        "admin": User("admin", hashlib.md5(b"admin").digest(), "admin"),
        "moder": User("moder", hashlib.md5(b"moder").digest(), "moder")
    }

    def login(self, username, password):
        psw_hash = hashlib.md5(bytes(password, 'utf-8')).digest()
        return username in self.store and psw_hash == self.store[username].psw_hash

    def registration(self, username, password):
        psw_hash = hashlib.md5(bytes(password, 'utf-8')).digest()
        self.store[username] = User(username, psw_hash, "user")

    def has_username(self, username):
        return username in self.store

    def find_user(self, username):
        if username in self.store:
            return self.store[username]
        else:
            raise Exception('not check')


class AesEncrypter:

    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, decrypt_data):
        cipher = AES.new(self.key, AES.MODE_CBC, 'init_val'.encode("utf8"))
        encrypt_data = cipher.encrypt(decrypt_data)
        return encrypt_data

    def decrypt(self, encrypt_data):
        cipher = AES.new(self.key, AES.MODE_CBC, 'init_val'.encode("utf8"))
        decrypt_data = cipher.decrypt(encrypt_data)
        return decrypt_data

class AuthService:
    def __init__(self, storage, aes_encrypter):
        self.storage = storage
        self.aes_encrypter = aes_encrypter

    def login(self, username, password):
        if self.storage.login(username, password):
            user = self.storage.find_user(username)
            user_str = str(pickle.dumps(user), 'utf-8')
            return self.aes_encrypter.encrypt(user_str)
        else:
            return ''

    def registration(self, username, password):
        if not self.storage.has_username(username):
            self.storage.registration(username, password)
        else:
            raise Exception("username is busy")

    def is_auth(self, session_id):
        user_str = self.aes_encrypter.decrypt(session_id)
        user = pickle.loads(bytes(user_str, 'utf-8'))
        return user


def server(auth_service):
    app = Flask(__name__)

    @app.route("/registration", methods=['POST'])
    def registration():
        r = request.json
        username = r['username']
        password = r['password']
        auth_service.registration(username, password)
        return "ok"

    @app.route("/login", methods=['POST'])
    def login():
        r = request.json
        username = r['username']
        password = r['password']
        session_id = auth_service.login(username, password)

        @after_this_request
        def set_cookie(response):
            response.set_cookie('session_id', str(session_id), max_age=10000)
            return response

        return "ok"

    @app.route("/logout", methods=['GET'])
    def logout():

        @after_this_request
        def clear_cookie(response):
            response.delete_cookie('session_id')
            return response

        return "logout ok"

    @app.route("/load", methods=['GET'])
    def load():
        if 'session_id' in request.cookies:
            session_id = request.cookies['session_id']
            user = auth_service.is_auth(session_id)
            if user is None:
                raise Exception("not auth1")
            else:
                return "success, your role: " + user.role
        else:
            raise Exception("not auth2")

    return app
