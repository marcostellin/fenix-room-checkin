import urllib2
import requests


class FenixRequest:

    def __init__(self):
        self.base_url = "https://fenix.tecnico.ulisboa.pt/api/fenix"
    
        self.api_version = "v1"

        self.endpoints = {
                    "person": "person",
                    }

    def get_person(self, access_token):

        url = self.base_url + "/" + self.api_version + "/" + self.endpoints["person"]
        params = {"access_token" : access_token}
        j = requests.get(url, params)

        return j  