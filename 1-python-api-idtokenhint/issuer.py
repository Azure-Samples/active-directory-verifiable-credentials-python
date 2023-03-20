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

issuanceConfig["callback"]["headers"]["api-key"] = config["apiKey"]
issuanceConfig["authority"] = config["IssuerAuthority"]
issuanceConfig["manifest"] = config["CredentialManifest"]
issuanceConfig["registration"]["clientName"] = "Python Verified ID sample"
if "pin" in issuanceConfig is not None:
    if int(issuanceConfig["pin"]["length"]) == 0:
        del issuanceConfig["pin"]

@app.route("/api/issuer/issuance-request", methods = ['GET'])
def issuanceRequest():
    """ This method is called from the UI to initiate the issuance of the verifiable credential """
    id = str(uuid.uuid4())
    cache.set( id, json.dumps({
      "status" : "request_created",
      "message": "Waiting for QR code to be scanned"
    }))
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
        """ don't use pin if user is on mobile device """
        if "Android" in request.headers['user-agent'] or "iPhone" in request.headers['user-agent']:
          del payload["pin"]
        else:
          pinCode = ''.join(str(randint(0,9)) for _ in range(int(payload["pin"]["length"])))
          payload["pin"]["value"] = pinCode
    if "claims" in payload is not None:
        if "given_name" in payload["claims"] is not None:
            payload["claims"]["given_name"] = "Megan"
        if "family_name" in payload["claims"] is not None:
            payload["claims"]["family_name"] = "Bowen"
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
    if request.headers['api-key'] != config["apiKey"]:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
    if issuanceResponse["requestStatus"] == "request_retrieved":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": "QR Code is scanned. Waiting for issuance to complete..."
        }
    elif issuanceResponse["requestStatus"] == "issuance_successful":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": "Credential successfully issued"
        }
    elif issuanceResponse["requestStatus"] == "issuance_error":
        cacheData = {
            "status": issuanceResponse["requestStatus"],
            "message": issuanceResponse["error"]["message"]
        }
    else:
        print("400 - Unsupported requestStatus: {0}".format(issuanceResponse["requestStatus"]) )
        return Response( jsonify({'error':'Unsupported requestStatus: {0}'.format(issuanceResponse["requestStatus"])}), status=400, mimetype='application/json')

    data = cache.get(issuanceResponse["state"])
    if data is None:
        print("400 - Unknown state: {0}".format(issuanceResponse["state"]) )
        return Response( jsonify({'error':'Unknown state: {0}'.format(issuanceResponse["state"])}), status=400, mimetype='application/json')
    print("200 - state: {0}".format(cacheData) )
    cache.set( issuanceResponse["state"], json.dumps(cacheData) )
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

@app.route("/api/issuer/get-manifest", methods = ['GET'])
def getManifest():
    return Response( json.dumps(config["manifest"]), status=200, mimetype='application/json')
