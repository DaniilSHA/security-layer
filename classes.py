import hashlib
import uuid

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


class Cache:
    def __init__(self):
        self.cache = {}

    def put(self, sessionId, username):
        self.cache[sessionId] = username

    def contains(self, sessionId):
        print(self.cache)
        return sessionId in self.cache


class AuthService:
    def __init__(self, storage, cache):
        self.storage = storage
        self.cache = cache

    def login(self, username, password):
        if self.storage.login(username, password):
            session_id = uuid.uuid4().hex
            self.cache.put(session_id, username)
            return session_id
        else:
            return ''

    def registration(self, username, password):
        if not self.storage.has_username(username):
            self.storage.registration(username, password)
        else:
            raise Exception("username is busy")

    def is_auth(self, session_id):
        return self.cache.contains(session_id)


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

    @app.route("/load", methods=['GET'])
    def load():
        if 'session_id' in request.cookies:
            session_id = request.cookies['session_id']
            if auth_service.is_auth(session_id):
                return "success"
            else:
                raise Exception("not auth1")
        else:
            raise Exception("not auth2")

    return app