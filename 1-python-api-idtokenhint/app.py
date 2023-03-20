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
import base64
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

def base64JwtTokenToJson(base64String):
    token = base64String.split(".")[1]
    token = token + "===="[len(token)%4:4]
    return json.loads(base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8'))

configFile = os.getenv('CONFIGFILE')
if configFile is None:
    configFile = sys.argv[1]
config = json.load(open(configFile))

config["apiKey"] = str(uuid.uuid4())

# Check that the manifestURL have the matching tenantId with the config file
manifestTenantId = config["CredentialManifest"].split("/")[5]
if config["azTenantId"] != manifestTenantId:
    raise ValueError("TenantId in ManifestURL " + manifestTenantId + " does not match tenantId in config file " + config["azTenantId"])

# Check that the issuer in the config file match the manifest
r = requests.get(config["CredentialManifest"])
resp = r.json()
manifest = base64JwtTokenToJson( resp["token"] )
config["manifest"] = manifest
if config["IssuerAuthority"] == "":
    config["IssuerAuthority"] = manifest["iss"]
if config["VerifierAuthority"] == "":
    config["VerifierAuthority"] = manifest["iss"]
if config["IssuerAuthority"] != manifest["iss"]:
    raise ValueError("Wrong IssuerAuthority in config file " + config["IssuerAuthority"] + ". Issuer in manifest is " + manifest["iss"])

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
config["msIdentityHostName"] = "https://verifiedid.did.msidentity.com/v1.0/"
# Check that the Credential Manifest URL is in the same tenant Region and throw an error if it's not
if False == config["CredentialManifest"].startswith( config["msIdentityHostName"] ):
    raise ValueError("Error in config file. CredentialManifest URL configured for wrong tenant region. Should start with: " + config["msIdentityHostName"])
    
#  check that we a) can acquire an access_token and b) that it has the needed permission for this sample    
result = msalCca.acquire_token_for_client( scopes="3db474b9-6a0c-4840-96ac-1fceb342124f/.default" )
if "access_token" in result:
    print( result['access_token'] )
    token = base64JwtTokenToJson( result["access_token"] )
    print( token["roles"])
    if "VerifiableCredential.Create.All" not in token["roles"]:
        raise ValueError("Access token do not have the required scope 'VerifiableCredential.Create.All'.")  
else:
    raise ValueError(result.get("error") + result.get("error_description"))
    
if __name__ == "__main__":
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
        'x-original-host': request.headers.get('x-original-host'),
        'IssuerAuthority': config["IssuerAuthority"],
        'VerifierAuthority': config["VerifierAuthority"],
        'manifestURL': config["CredentialManifest"],
        'clientId': config["azClientId"],
        'configFile': configFile
    }
    return Response( json.dumps(result), status=200, mimetype='application/json')

if __name__ == "__main__":
    port = os.getenv('PORT')
    if port is None:
        port = 8080
    app.run(host="0.0.0.0", port=port)