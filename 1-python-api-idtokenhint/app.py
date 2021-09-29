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

cacheConfig = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300
}
app = Flask(__name__,static_url_path='',static_folder='static',template_folder='static')

app.config.from_mapping(cacheConfig)
cache = Cache(app)

log = logging.getLogger() 
log.setLevel(logging.INFO)

config = json.load(open(sys.argv[1]))

msalCca = msal.ConfidentialClientApplication( config["azClientId"], 
    authority="https://login.microsoftonline.com/" + config["azTenantId"],
    client_credential=config["azClientSecret"],
    )

import issuer
import verifier

@app.route('/')
def root():
    return app.send_static_file('index.html')

@app.route("/echo", methods = ['GET'])
def echoApi():
    result = {
        'date': datetime.datetime.utcnow().isoformat(),
        'api': request.url,
        'Host': request.headers.get('host'),
        'x-forwarded-for': request.headers.get('x-forwarded-for'),
        'x-original-host': request.headers.get('x-original-host')
    }
    return Response( json.dumps(result), status=200, mimetype='application/json')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)