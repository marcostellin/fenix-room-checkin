import urllib2
import requests
import json


class FenixRequest:

    def __init__(self):
        self.base_url = "https://fenix.tecnico.ulisboa.pt/api/fenix"
    
        self.api_version = "v1"

        self.endpoints = {
                    "person": "person",
                    "space" : "spaces",
                    }

    def get_person(self, access_token):

        url = self.base_url + "/" + self.api_version + "/" + self.endpoints["person"]
        params = {"access_token" : access_token}
        j = requests.get(url, params)

        return json.loads(j.text)  

    def get_space_id(self, space_id):

        url = url = self.base_url + "/" + self.api_version + "/" + self.endpoints["space"] + "/" + space_id
        j = requests.get(url)

        return json.loads(j.text)