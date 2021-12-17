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

apiKey = str(uuid.uuid4())

presentationConfig["callback"]["headers"]["api-key"] = apiKey
presentationConfig["authority"] = config["VerifierAuthority"]
presentationConfig["presentation"]["requestedCredentials"][0]["acceptedIssuers"][0] = config["IssuerAuthority"]
print( presentationConfig )

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
    response = Response( json.dumps(resp), status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@app.route("/api/verifier/presentation-request-callback", methods = ['POST'])
def presentationRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    presentationResponse = request.json
    print(presentationResponse)
    if request.headers['api-key'] != apiKey:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
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
            "lastName": presentationResponse["issuers"][0]["claims"]["lastName"],
            "presentationResponse": presentationResponse
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
        response = Response( json.dumps(cacheData), status=200, mimetype='application/json')
    else:
        response = Response( "", status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route("/api/verifier/presentation-response-b2c", methods = ['POST'])
def presentationResponseB2C():
    presentationResponse = request.json
    id = presentationResponse["id"]
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        if cacheData["status"] == "presentation_verified":
            claims = cacheData["presentationResponse"]["issuers"][0]["claims"]
            claimsExtra = {
               'vcType': presentationConfig["presentation"]["requestedCredentials"][0]["type"],
               'vcIss': cacheData["presentationResponse"]["issuers"][0]["authority"],
               'vcSub': cacheData["presentationResponse"]["subject"],
               'vcKey': cacheData["presentationResponse"]["subject"].replace("did:ion:", "did.ion.").split(":")[0].replace("did.ion.", "did:ion:")
            }
            responseBody = {**claimsExtra, **claims} # merge
            return Response( json.dumps(responseBody), status=200, mimetype='application/json')

    errmsg = {
        'version': '1.0.0', 
        'status': 400,
        'userMessage': 'Verifiable Credentials not presented'
        }
    return Response( json.dumps(errmsg), status=409, mimetype='application/json')
