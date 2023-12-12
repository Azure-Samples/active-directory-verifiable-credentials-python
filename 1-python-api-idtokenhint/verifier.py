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
import jwt, base64
import msal

from __main__ import app
from __main__ import cache
from __main__ import log
from __main__ import config
from __main__ import msalCca
from __main__ import base64JwtTokenToJson

presentationConfig = {
  "authority": "...set in code...",
  "includeQRCode": False,
  "callback": {
    "url": "...set in code...",
    "state": "...set in code...",
    "headers": {
      "api-key": "...set in code..."
    }
  },
  "registration": {
    "clientName": config["clientName"],
    "purpose": config["purpose"]
  },
  "includeReceipt": True,
  "requestedCredentials": [
    {
      "type": config["CredentialType"],
      "acceptedIssuers": [ config["acceptedIssuers"] ],
      "configuration": {
        "validation": {
          "allowRevoked": True,
          "validateLinkedDomain": True
        }
      }    
    }
  ]
}

idx = sys.argv.index('-p') if '-p' in sys.argv else -1
if idx >= 0:
    print("Loading presentationRequest from file: " + sys.argv[idx+1])
    presentationConfig = json.load(open(sys.argv[idx+1]))

presentationConfig["authority"] = config["DidAuthority"]
presentationConfig["callback"]["headers"]["api-key"] = config["apiKey"]

@app.route("/api/verifier/presentation-request", methods = ['GET'])
def presentationRequest():
    """ This method is called from the UI to initiate the presentation of the verifiable credential """
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
    payload = presentationConfig.copy()
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "api/request-callback"
    payload["callback"]["state"] = id
    print( json.dumps(payload) )
    post_headers = { "content-type": "application/json", "Authorization": "Bearer " + accessToken }
    client_api_request_endpoint = config["msIdentityHostName"] + "verifiableCredentials/createPresentationRequest"
    print( client_api_request_endpoint )
    r = requests.post( client_api_request_endpoint
                    , headers=post_headers, data=json.dumps(payload))
    resp = r.json()
    print(resp)
    resp["id"] = id            
    response = Response( json.dumps(resp), status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route("/api/verifier/get-presentation-details", methods = ['GET'])
def getPresentationDetails():
    respData = {
    'clientName': presentationConfig["registration"]["clientName"],
    'purpose': presentationConfig["registration"]["purpose"],
    'DidAuthority': config["DidAuthority"],
    'type': presentationConfig["requestedCredentials"][0]["type"],
    'acceptedIssuers': presentationConfig["requestedCredentials"][0]["acceptedIssuers"]
    }
    return Response( json.dumps(respData), status=200, mimetype='application/json')

@app.route("/api/verifier/load-template", methods = ['POST'])
def loadTemplate():
    """ 
    UI passes a template for presentation request so we can request other credentials
    """
    body = request.data.decode()
    buf = ""
    for line in body.splitlines():
      if line.lstrip().startswith("//") == False:
        buf = buf + line
    template = json.loads(buf)
    print(template)
    global presentationConfig
    presentationConfig = template
    presentationConfig["authority"] = config["DidAuthority"]
    presentationConfig["callback"]["headers"]["api-key"] = config["apiKey"]
    response = Response( json.dumps({'status': 'template loaded'}), status=200, mimetype='application/json')
    return response
