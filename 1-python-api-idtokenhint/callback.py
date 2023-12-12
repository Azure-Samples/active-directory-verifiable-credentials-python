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
from __main__ import base64JwtTokenToJson


@app.route("/api/request-callback", methods = ['POST'])
def presentationRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    callbackBody = request.json
    print(callbackBody)
    if request.headers['api-key'] != config["apiKey"]:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
    if callbackBody["requestStatus"] == "request_retrieved":
        cacheData = {
            "status": callbackBody["requestStatus"],
            "message": "QR Code is scanned. Waiting for validation..."
        }
    elif callbackBody["requestStatus"] == "issuance_successful":
        cacheData = {
            "status": callbackBody["requestStatus"],
            "message": "Credential successfully issued"
        }
    elif callbackBody["requestStatus"] == "issuance_error":
        cacheData = {
            "status": callbackBody["requestStatus"],
            "message": callbackBody["error"]["message"]
        }
    elif callbackBody["requestStatus"] == "presentation_verified":
        cacheData = {
            "status": callbackBody["requestStatus"],
            "message": "Presentation received",
            "payload": callbackBody["verifiedCredentialsData"],
            "subject": callbackBody["subject"],
            "presentationResponse": callbackBody
        }
        if callbackBody["receipt"] is not None:
          vp_token = base64JwtTokenToJson(callbackBody["receipt"]["vp_token"])
          vc = base64JwtTokenToJson(vp_token["vp"]["verifiableCredential"][0])
          cacheData["jti"] = vc["jti"]  
    elif callbackBody["requestStatus"] == "presentation_error":
        cacheData = {
            "status": callbackBody["requestStatus"],
            "message": callbackBody["error"]["message"]
        }
    else:
        print("400 - Unsupported requestStatus: {0}".format(callbackBody["requestStatus"]) )
        return Response( jsonify({'error':'Unsupported requestStatus: {0}'.format(callbackBody["requestStatus"])}), status=400, mimetype='application/json')

    data = cache.get(callbackBody["state"])
    if data is None:
        print("400 - Unknown state: {0}".format(callbackBody["state"]) )
        return Response( jsonify({'error':'Unknown state: {0}'.format(callbackBody["state"])}), status=400, mimetype='application/json')
    print("200 - state: {0}".format(cacheData) )
    cache.set( callbackBody["state"], json.dumps(cacheData) )
    return ""

@app.route("/api/request-status", methods = ['GET'])
def presentationRequestStatus():
    """ this function is called from the UI polling for a response from the Verified ID Service.
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
        response = Response( "", status=400, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
