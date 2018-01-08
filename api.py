import json


class Error:

    def __init__(self):
        self.BAD_REQUEST = '400'
        self.NOT_FOUND = '404'
        self.NOT_AUTHORIZED = '410'
        self.CONFLICT = '409'


    def bad_request(self, msg):
        return {"error" : msg, "number" : self.BAD_REQUEST}

    def not_found(self, msg):
        return {"error" : msg, "number" : self.NOT_FOUND}

    def not_authorized(self, msg):
        return {"error" : msg, "number" : self.NOT_AUTHORIZED}

    def conflict(self, msg):
        return {"error" : msg, "number" : self.CONFLICT}