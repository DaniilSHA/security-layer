from classes import Storage, Cache, AuthService, server

storage = Storage()
cache = Cache()
auth_service = AuthService(storage, cache)
server = server(auth_service)