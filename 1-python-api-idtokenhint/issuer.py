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

issuanceConfig = {
  "includeQRCode": False,
  "callback": {
    "url": "...set at runtime...",
    "state": "...set at runtime...",
    "headers": {
      "api-key": "...set at runtime..."
    }
  },
  "authority": "...set at runtime...",
  "registration": {
    "clientName": config["clientName"],
    "purpose": config["purpose"]
  },
  "type": "ignore-this",
  "manifest": config["CredentialManifest"],
  "pin": {
    "value": "1234",
    "length": 4
  },
  "claims": {
    "given_name": "FIRSTNAME",
    "family_name": "LASTNAME"
  }
}

idx = sys.argv.index('-i') if '-i' in sys.argv else -1
if idx >= 0:
    print("Loading issuanceRequest from file: " + sys.argv[idx+1])
    issuanceConfig = json.load(open(sys.argv[idx+1]))

issuanceConfig["authority"] = config["DidAuthority"]
issuanceConfig["callback"]["headers"]["api-key"] = config["apiKey"]

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
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "api/request-callback"
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

@app.route("/api/issuer/get-manifest", methods = ['GET'])
def getManifest():
    return Response( json.dumps(config["manifest"]), status=200, mimetype='application/json')
