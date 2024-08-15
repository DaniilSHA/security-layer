from classes import Storage, AesEncrypter, AuthService, server

storage = Storage()
aes_encrypter = AesEncrypter()
auth_service = AuthService(storage, aes_encrypter)
server = server(auth_service)