// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Modified by Hollins University: Face Check always required, revoked credentials
// rejected, token logging removed, template and B2C endpoints removed.

// Verifiable Credentials Verifier Sample

///////////////////////////////////////////////////////////////////////////////////////
// Node packages
var express = require('express')
var bodyParser = require('body-parser')
// mod.cjs
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
var mainApp = require('./app.js');

///////////////////////////////////////////////////////////////////////////////////////
// Setup the presentation request payload template
var presentationConfig = {
  "authority": "...set in code...",
  "includeQRCode": false,
  "callback": {
    "url": "...set in code...",
    "state": "...set in code...",
    "headers": {
      "api-key": "...set in code..."
    }
  },
  "registration": {
    "clientName": "...set in code...",
    "purpose": "...set in code..."
  },
  "includeReceipt": true,
  "requestedCredentials": [
    {
      "type": "...set in code...",
      "acceptedIssuers": [],
      "configuration": {
        "validation": {
          "allowRevoked": false,
          "validateLinkedDomain": true
        }
      }    
    }
  ]
};
// see if we got a template from 1) envvar or 2) cmd argv
var requestConfigFile = process.env.PRESENTATIONFILE;
if ( !requestConfigFile ) {
  var idx = process.argv.findIndex((el) => el == "-p");
  if ( idx != -1 ) {
    requestConfigFile = process.argv[idx+1];
  }
}
if ( requestConfigFile ) {
  presentationConfig = require( requestConfigFile );
}
function updatePresentationConfig(presentationConfig) {
  if ( mainApp.config["clientName"] ) {
    presentationConfig.registration.clientName = mainApp.config["clientName"];
  }
  if ( presentationConfig.registration.clientName.startsWith("...") ) {
    presentationConfig.registration.clientName = "Hollins University";
  }
  if ( mainApp.config["purpose"] ) {
    presentationConfig.registration.purpose = mainApp.config["purpose"];
  }
  if ( presentationConfig.registration.purpose.startsWith("...") ) {
    presentationConfig.registration.purpose = "To confirm your identity and create a Temporary Access Pass";
  }
  if ( presentationConfig.callback.headers ) {
    presentationConfig.callback.headers['api-key'] = mainApp.config["apiKey"];
  }
}
updatePresentationConfig( presentationConfig );
if ( mainApp.config["CredentialType"] ) {
  presentationConfig.requestedCredentials[0].type = mainApp.config["CredentialType"]
}
presentationConfig.authority = mainApp.config["DidAuthority"]
// only trust the issuer(s) listed in settings for the requested credential type
if ( mainApp.config["acceptedIssuers"] && mainApp.config["acceptedIssuers"].includes("did:") ) {
  presentationConfig.requestedCredentials[0].acceptedIssuers = mainApp.config["acceptedIssuers"].split(";");
}

// Face Check is always required. tap.js also enforces the score on the callback.
presentationConfig.requestedCredentials[0].configuration.validation.faceCheck = {
  sourcePhotoClaimName: mainApp.config["sourcePhotoClaimName"] || "photo",
  matchConfidenceThreshold: parseInt(mainApp.config["matchConfidenceThreshold"]) || 70
};

///////////////////////////////////////////////////////////////////////////////////////
// Simple in-memory rate limit on creating presentation requests. Each request
// uses a Key Vault signing operation, so this keeps anyone from spamming Start.
// Campus users share one public IP, so the per-IP limit is generous and the
// per-session limit does most of the work.
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_PER_SESSION = 3;
const RATE_PER_IP = 20;
const rateHits = new Map();

function clientIp(req) {
  // App Service adds the client address as the last X-Forwarded-For entry, with a port.
  var xff = (req.headers['x-forwarded-for'] || '').split(',').pop().trim();
  var ip = xff || req.socket.remoteAddress || 'unknown';
  return /^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip) ? ip.split(':')[0] : ip;
}
function overLimit(key, max) {
  var now = Date.now();
  var recent = (rateHits.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (recent.length >= max) {
    rateHits.set(key, recent);
    return true;
  }
  recent.push(now);
  rateHits.set(key, recent);
  return false;
}
setInterval(() => {
  var now = Date.now();
  for (const [key, times] of rateHits) {
    if (!times.some((t) => now - t < RATE_WINDOW_MS)) rateHits.delete(key);
  }
}, RATE_WINDOW_MS).unref();

///////////////////////////////////////////////////////////////////////////////////////
// This method is called from the UI to initiate the presentation of the credential
mainApp.app.get('/api/verifier/presentation-request', async (req, res) => {
  mainApp.requestTrace( req );
  var id = req.session.id;

  var ip = clientIp( req );
  if ( overLimit( 'session:' + id, RATE_PER_SESSION ) || overLimit( 'ip:' + ip, RATE_PER_IP ) ) {
    console.log( JSON.stringify({ event: 'rate_limited', ip: ip, time: new Date().toISOString() }) );
    res.status(429).json({ 'error': 'Too many attempts. Wait 10 minutes, then try again.' });
    return;
  }

  // get the Access Token
  var accessToken = "";
  try {
    const result = await mainApp.msalCca.acquireTokenByClientCredential(mainApp.msalClientCredentialRequest);
    if ( result ) {
      accessToken = result.accessToken;
    }
  } catch {
      console.log( "failed to get access token" );
      res.status(401).json({
        'error': 'Could not acquire access token to call Verified ID'
        });  
      return; 
  }

  presentationConfig.authority = mainApp.config["DidAuthority"]
  presentationConfig.callback.url = `https://${req.hostname}/api/request-callback`;
  presentationConfig.callback.state = id;

  var client_api_request_endpoint = `${mainApp.config.msIdentityHostName}verifiableCredentials/createPresentationRequest`;
  var payload = JSON.stringify(presentationConfig);
  // createPresentationRequest with faceCheck must use the beta endpoint
  if ( payload.includes("faceCheck")) {
    client_api_request_endpoint = client_api_request_endpoint.replace("/v1.0/", "/beta/");
  }
  console.log( `Request Service API request: ${client_api_request_endpoint}` );
  const fetchOptions = {
    method: 'POST',
    body: payload,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': payload.length.toString(),
      'Authorization': `Bearer ${accessToken}`
    }
  };

  console.time("createPresentationRequest");
  const response = await fetch(client_api_request_endpoint, fetchOptions);
  var resp = await response.json()
  console.timeEnd("createPresentationRequest");

  // The response contains the URI to the request, which Authenticator downloads
  // after it scans the QR code shown by the UI.
  resp.id = id;                              // add id so browser can pull status
  console.log( `VC Client API response status: ${response.status}` );
  
  if ( response.status > 299 ) {
    var inner = (resp.error && resp.error.innererror) || {};
    resp.error_description = `[${inner.code}] ${resp.error ? resp.error.message : ''} ${inner.message || ''}`;
    console.log( resp.error_description );
    res.status(400).json( resp );  
  } else {
    // prep an initial session state
    var session = await mainApp.getSessionDataWrapper( id );
    if ( session ) {
      session.sessionData = {
        "status" : "request_created",
        "message": "Waiting for QR code to be scanned"
      };
      mainApp.sessionStore.set( id, session);
    }
    res.status(200).json( resp );       
  }
  
})

///////////////////////////////////////////////////////////////////////////////////////
// Return presentation request details to the UI
mainApp.app.get('/api/verifier/get-presentation-details', async (req, res) => {
  mainApp.requestTrace( req );
  res.status(200).json({
    'clientName': presentationConfig.registration.clientName,
    'purpose': presentationConfig.registration.purpose,
    'DidAuthority': mainApp.config["DidAuthority"],
    'type': presentationConfig.requestedCredentials[0].type,
    'acceptedIssuers': presentationConfig.requestedCredentials[0].acceptedIssuers,
    'sourcePhotoClaimName': mainApp.config["sourcePhotoClaimName"]
    });   
})

// Removed: /api/verifier/load-template (let anyone replace the presentation request)
// Removed: /api/verifier/presentation-response-b2c (Azure AD B2C integration, not used)
