import urllib2
from flask import request


class FenixRequest:

    base_url = "https://fenix.tecnico.ulisboa.pt/api/fenix"
    
    api_version = "v1"

    endpoints = {
                    "person": "person",
                }

    def get_person(access_token):

        url = self.base_url + "/" + self.api_version + "/" + self.endpoints["person"]
        params = {"access_token" : access_token}
        j = request.get(url, params)

        return j  