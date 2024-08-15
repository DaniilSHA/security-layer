import codecs
import pickle

from classes import Storage, AesEncrypter, AuthService, server, User

storage = Storage()
aes_encrypter = AesEncrypter()
auth_service = AuthService(storage, aes_encrypter)
server = server(auth_service)

fail_user = User("admin", "faik", "admin")
dump = pickle.dumps(fail_user)
user_str = codecs.encode(dump, 'base64').decode()
faik_cookie = aes_encrypter.encrypt(user_str)
print(faik_cookie)