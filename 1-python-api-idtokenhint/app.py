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
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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

if config["azCertificateName"] != "":
    with open(config["azCertificatePrivateKeyLocation"], "rb") as file:
        private_key = file.read()
    with open(config["azCertificateLocation"]) as file:
        public_certificate = file.read()
    cert = load_pem_x509_certificate(data=bytes(public_certificate, 'UTF-8'), backend=default_backend())
    thumbprint = (cert.fingerprint(hashes.SHA1()).hex())
    print("Cert based auth using thumbprint: " + thumbprint)    
    msalCca = msal.ConfidentialClientApplication( config["azClientId"], 
       authority="https://login.microsoftonline.com/" + config["azTenantId"],
        client_credential={
            "private_key": private_key,
            "thumbprint": thumbprint,
            "public_certificate": public_certificate
        }
    )    

# Check if it is an EU tenant and set up the endpoint for it
r = requests.get("https://login.microsoftonline.com/" + config["azTenantId"] + "/v2.0/.well-known/openid-configuration")
resp = r.json()
print("tenant_region_scope = " + resp["tenant_region_scope"])
config["tenant_region_scope"] = resp["tenant_region_scope"]
config["msIdentityHostName"] = "https://beta.did.msidentity.com/v1.0/"
if resp["tenant_region_scope"] == "EU":
    config["msIdentityHostName"] = "https://beta.eu.did.msidentity.com/v1.0/"

# Check that the Credential Manifest URL is in the same tenant Region and throw an error if it's not
if False == config["CredentialManifest"].startswith( config["msIdentityHostName"] ):
    raise ValueError("Error in config file. CredentialManifest URL configured for wrong tenant region. Should start with: " + config["msIdentityHostName"])
    
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