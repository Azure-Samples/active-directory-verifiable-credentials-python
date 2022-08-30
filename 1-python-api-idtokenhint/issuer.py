#!/usr/bin/python

from flask import Flask
from flask import request,Response,redirect
from flask_caching import Cache
from flask.json import jsonify
import json
import logging
import sys, os, tempfile, uuid, time, datetime
import configparser
import argparse
import requests
from random import randint
import msal

from __main__ import app
from __main__ import cache
from __main__ import log
from __main__ import config
from __main__ import msalCca

issuanceFile = os.getenv('ISSUANCEFILE')
if issuanceFile is None:
    issuanceFile = sys.argv[2]
fI = open(issuanceFile,)
issuanceConfig = json.load(fI)
fI.close()  

apiKey = str(uuid.uuid4())

issuanceConfig["callback"]["headers"]["api-key"] = apiKey
issuanceConfig["authority"] = config["IssuerAuthority"]
issuanceConfig["manifest"] = config["CredentialManifest"]
if "pin" in issuanceConfig is not None:
    if int(issuanceConfig["pin"]["length"]) == 0:
        del issuanceConfig["pin"]

@app.route("/api/issuer/issuance-request", methods = ['GET'])
def issuanceRequest():
    """ This method is called from the UI to initiate the issuance of the verifiable credential """
    id = str(uuid.uuid4())
    accessToken = ""
    result = msalCca.acquire_token_for_client( scopes="3db474b9-6a0c-4840-96ac-1fceb342124f/.default" )
    if "access_token" in result:
        print( result['access_token'] )
        accessToken = result['access_token']
    else:
        print(result.get("error") + result.get("error_description"))

    payload = issuanceConfig.copy()
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "api/issuer/issuance-request-callback"
    payload["callback"]["state"] = id
    pinCode = 0
    if "pin" in payload is not None:
        pinCode = ''.join(str(randint(0,9)) for _ in range(int(payload["pin"]["length"])))
        payload["pin"]["value"] = pinCode
    # if payload["type"] == "VerifiedEmployee":
        # payload["claims"]["displayName"] = "Adeeb A."
        # payload["claims"]["givenName"] = "Adeeb"
        # payload["claims"]["jobTitle"] = "On-site Data tech"
        # payload["claims"]["preferredLanguage"] = "ENG"
        # payload["claims"]["surname"] = "Ahmed"
        # payload["claims"]["mail"] = "deeb@outlook.com"
        # payload["claims"]["revocationId"] = "123"
        # payload["claims"]["photo"] = ":)"
    # if payload["type"] == "VerifiedCredentialExpert":
    #     payload["claims"]["given_name"] = "Megan"
    #     payload["claims"]["family_name"] = "Bowen"

    print( json.dumps(payload) )
    post_headers = { "content-type": "application/json", "Authorization": "Bearer " + accessToken }
    client_api_request_endpoint = config["msIdentityHostName"] + "verifiableCredentials/createIssuanceRequest"
    print( client_api_request_endpoint )
    r = requests.post( client_api_request_endpoint
                    , headers=post_headers, data=json.dumps(payload))
    resp = r.json()
    print(resp)
    resp["id"] = id
    if "pin" in payload is not None:
        resp["pin"] = pinCode
    #print(resp)
    return Response( json.dumps(resp), status=200, mimetype='application/json')

@app.route("/api/issuer/issuance-request-callback", methods = ['POST'])
def issuanceRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    issuanceResponse = request.json
    print(issuanceResponse)
    if request.headers['api-key'] != apiKey:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
    if issuanceResponse["requestStatus"] == "request_retrieved":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": "QR Code is scanned. Waiting for issuance to complete..."
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    if issuanceResponse["requestStatus"] == "issuance_successful":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": "Credential successfully issued"
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    if issuanceResponse["requestStatus"] == "issuance_error":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": issuanceResponse["error"]["message"]
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    return ""

@app.route("/api/issuer/issuance-response", methods = ['GET'])
def issuanceRequestStatus():
    """ this function is called from the UI polling for a response from the AAD VC Service.
    when a callback is recieved at the presentationCallback service the session will be updated
     """
    id = request.args.get('id')
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        browserData = {
            'status': cacheData["status"],
            'message': cacheData["message"]
        }
        return Response( json.dumps(browserData), status=200, mimetype='application/json')
    else:
        return ""
