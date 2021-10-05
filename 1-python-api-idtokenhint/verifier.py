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

fP = open(sys.argv[3],)
presentationConfig = json.load(fP)
fP.close()  

presentationConfig["authority"] = config["VerifierAuthority"]
presentationConfig["presentation"]["requestedCredentials"][0]["acceptedIssuers"][0] = config["IssuerAuthority"]

@app.route("/api/verifier/presentation-request", methods = ['GET'])
def presentationRequest():
    """ This method is called from the UI to initiate the presentation of the verifiable credential """
    id = str(uuid.uuid4())
    accessToken = ""
    result = msalCca.acquire_token_for_client( scopes="bbb94529-53a3-4be5-a069-7eaf2712b826/.default" )
    if "access_token" in result:
        print( result['access_token'] )
        accessToken = result['access_token']
    else:
        print(result.get("error") + result.get("error_description"))
    payload = presentationConfig.copy()
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "/api/verifier/presentation-request-callback"
    payload["callback"]["state"] = id
    print( json.dumps(payload) )
    post_headers = { "content-type": "application/json", "Authorization": "Bearer " + accessToken }
    client_api_request_endpoint = "https://beta.did.msidentity.com/v1.0/" + config["azTenantId"] + "/verifiablecredentials/request"
    r = requests.post( client_api_request_endpoint
                    , headers=post_headers, data=json.dumps(payload))
    resp = r.json()
    print(resp)
    resp["id"] = id            
    return Response( json.dumps(resp), status=200, mimetype='application/json')

@app.route("/api/verifier/presentation-request-callback", methods = ['POST'])
def presentationRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    presentationResponse = request.json
    print(presentationResponse)
    if presentationResponse["code"] == "request_retrieved":
        cacheData = {
            "status": presentationResponse["code"],
            "message": "QR Code is scanned. Waiting for validation..."
        }
        cache.set( presentationResponse["state"], json.dumps(cacheData) )
        return ""
    if presentationResponse["code"] == "presentation_verified":
        cacheData = {
            "status": presentationResponse["code"],
            "message": "Presentation received",
            "payload": presentationResponse["issuers"],
            "subject": presentationResponse["subject"],
            "firstName": presentationResponse["issuers"][0]["claims"]["firstName"],
            "lastName": presentationResponse["issuers"][0]["claims"]["lastName"]
        }
        cache.set( presentationResponse["state"], json.dumps(cacheData) )
        return ""
    return ""

@app.route("/api/verifier/presentation-response", methods = ['GET'])
def presentationRequestStatus():
    """ this function is called from the UI polling for a response from the AAD VC Service.
     when a callback is recieved at the presentationCallback service the session will be updated
     this method will respond with the status so the UI can reflect if the QR code was scanned and with the result of the presentation
     """
    id = request.args.get('id')
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        return Response( json.dumps(cacheData), status=200, mimetype='application/json')
    else:
        return ""
