// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Modified by Hollins University: TAP issuance after verified presentation,
// one-time TAP delivery, session ownership check, and reduced logging.

///////////////////////////////////////////////////////////////////////////////////////
// Node packages
var base64url = require('base64url')
var crypto = require('crypto');
var mainApp = require('./app.js');
var { issueTap, Refusal, audit } = require('./tap.js');

// Callbacks can include a photo claim, so allow a few MB but no more.
const MAX_CALLBACK_BYTES = 5 * 1024 * 1024;

///////////////////////////////////////////////////////////////////////////////////////
// Helpers
function getSession( id ) {
  return new Promise((resolve) => {
    mainApp.sessionStore.get( id, (error, session) => resolve(error ? null : session) );
  });
}
function setSession( id, session ) {
  return new Promise((resolve, reject) => {
    mainApp.sessionStore.set( id, session, (error) => error ? reject(error) : resolve() );
  });
}
function apiKeyMatches( provided ) {
  var expected = Buffer.from( String(mainApp.config["apiKey"]) );
  var given = Buffer.from( String(provided || '') );
  return given.length === expected.length && crypto.timingSafeEqual( given, expected );
}
function getJti( callbackEvent ) {
  try {
    var token = callbackEvent.receipt && callbackEvent.receipt.vp_token;
    if ( !token ) return undefined;
    if ( Array.isArray(token) ) token = token[0];
    var vp = JSON.parse(base64url.decode(token.split(".")[1]));
    var vc = JSON.parse(base64url.decode(vp.vp.verifiableCredential[0].split(".")[1]));
    return vc.jti;
  } catch {
    return undefined;
  }
}

///////////////////////////////////////////////////////////////////////////////////////
// Runs after we have answered the callback. Issues the TAP (or records why not)
// and stores the result for the browser to pick up once.
async function finishPresentation( callbackEvent ) {
  try {
    var result;
    try {
      var tap = await issueTap( callbackEvent );
      result = {
        tap: tap.temporaryAccessPass,
        tapMinutes: tap.lifetimeInMinutes,
        tapAccount: tap.userPrincipalName
      };
    } catch (e) {
      audit('tap_refused', { requestId: callbackEvent.requestId, reason: e.message });
      result = {
        tapError: e instanceof Refusal
          ? e.message
          : 'We could not create a pass. Please contact the help desk.'
      };
    }

    var session = await getSession( callbackEvent.state );
    if ( !session ) {
      // The browser session expired or the app restarted. A TAP may exist that
      // nobody can see. It is one-time use and expires on its own.
      audit('tap_session_lost', { requestId: callbackEvent.requestId, issued: !!result.tap });
      return;
    }
    session.sessionData = {
      "status": "presentation_verified",
      "message": result.tap ? "Your Temporary Access Pass is ready" : "Presentation received",
      "payload": callbackEvent.verifiedCredentialsData,
      "subject": callbackEvent.subject,
      "jti": getJti( callbackEvent ),
      ...result
    };
    await setSession( callbackEvent.state, session );
  } catch (e) {
    // Never let an error here crash the process.
    audit('tap_finish_error', { requestId: callbackEvent.requestId, reason: e.message });
  }
}

///////////////////////////////////////////////////////////////////////////////////////
/**
 * Called by the Verified ID service when the user scans the QR code and presents a credential.
 */
mainApp.app.post('/api/request-callback', (req, res) => {
  var body = '';
  var tooLarge = false;
  req.on('data', function (data) {
    if ( tooLarge ) return;
    body += data;
    if ( body.length > MAX_CALLBACK_BYTES ) tooLarge = true;
  });
  req.on('end', async function () {
    try {
      mainApp.requestTrace( req );
      if ( tooLarge ) {
        res.status(413).json({ 'error': 'payload too large' });
        return;
      }
      // the api-key is set at startup in app.js. If not present in callback, the call is rejected
      if ( !apiKeyMatches( req.headers['api-key'] ) ) {
        res.status(401).json({ 'error': 'api-key wrong or missing' });
        return;
      }
      var callbackEvent;
      try {
        callbackEvent = JSON.parse( body );
      } catch {
        res.status(400).json({ 'error': 'invalid JSON' });
        return;
      }
      // Log the status only. The body holds claims, the photo, and tokens.
      console.log( `callback: ${callbackEvent.requestStatus} for request ${callbackEvent.requestId}` );

      var session = await getSession( callbackEvent.state );
      if ( !session ) {
        console.log( `400 - Unknown state for request ${callbackEvent.requestId}` );
        res.status(400).json({ 'error': 'Unknown state' });
        return;
      }

      switch ( callbackEvent.requestStatus ) {
        // QR code scanned
        case "request_retrieved":
          session.sessionData = {
            "status": callbackEvent.requestStatus,
            "message": "QR code is scanned. Waiting for validation..."
          };
          break;

        // Verified ID has verified the presentation
        case "presentation_verified":
          // Ignore a repeated callback for the same request so we never issue twice.
          if ( session.tapRequestId === callbackEvent.requestId ) {
            res.send();
            return;
          }
          session.tapRequestId = callbackEvent.requestId;
          // Keep the status as request_retrieved so the page keeps polling
          // until the TAP result is ready.
          session.sessionData = {
            "status": "request_retrieved",
            "message": "Credential verified. Creating your pass..."
          };
          await setSession( callbackEvent.state, session );
          res.send();
          finishPresentation( callbackEvent ); // continues after we answer the service
          return;

        case "presentation_error":
          session.sessionData = {
            "status": callbackEvent.requestStatus,
            "message": callbackEvent.error ? callbackEvent.error.message : "Presentation failed",
            "payload": callbackEvent.error ? callbackEvent.error.code : undefined
          };
          break;

        default:
          console.log( `400 - Unsupported requestStatus: ${callbackEvent.requestStatus}` );
          res.status(400).json({ 'error': `Unsupported requestStatus: ${callbackEvent.requestStatus}` });
          return;
      }

      await setSession( callbackEvent.state, session );
      res.send();
    } catch (e) {
      console.log( `500 - callback error: ${e.message}` );
      if ( !res.headersSent ) res.status(500).json({ 'error': 'internal error' });
    }
  });
})

/**
 * Polled by the page. Only the browser session that started the request can read
 * its status, and a TAP is returned exactly once.
 */
mainApp.app.get('/api/request-status', async (req, res) => {
  try {
    var id = req.query.id;
    mainApp.requestTrace( req );
    res.set('Cache-Control', 'no-store');

    if ( !id || id !== req.session.id ) {
      res.status(403).json({ 'error': 'This request belongs to a different browser session.' });
      return;
    }
    var session = await getSession( id );
    if ( !session || !session.sessionData ) {
      res.status(400).json({ 'error': 'Unknown state' });
      return;
    }

    var data = session.sessionData;
    if ( data.tap ) {
      var firstView = { ...data };
      session.sessionData = {
        ...data,
        "tap": null,
        "tapDelivered": true,
        "message": "Your pass was already shown. If you did not save it, start over."
      };
      await setSession( id, session );
      res.status(200).json( firstView );
      return;
    }
    res.status(200).json( data );
  } catch (e) {
    console.log( `500 - status error: ${e.message}` );
    res.status(500).json({ 'error': 'internal error' });
  }
})
