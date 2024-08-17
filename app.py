import codecs
import pickle

from classes import Storage, JwtEmitter, AuthService, server, User

storage = Storage()
jwt_emitter = JwtEmitter()
auth_service = AuthService(storage, jwt_emitter)
server = server(auth_service)