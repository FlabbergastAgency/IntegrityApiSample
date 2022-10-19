var express = require("express");
var { google } = require("googleapis");
const playintegrity = google.playintegrity("v1");
const info = require("./app_info.json");
const credentials = require("./google_app_credentials.json");
const packageName = JSON.parse(JSON.stringify(info)).package;
const privatekey = JSON.parse(JSON.stringify(credentials));
const ALLOWED_WINDOW_MILLIS = 1900000; 
const status = {
  COMPROMISED: "compromised",
  OK: "ok",
};

var app = express();
app.get("/nonce", nonce)
app.get("/verdict", tokenVerdict);

app.listen(3000, function () {
  console.log("Listening on port 3000!");
});

async function nonce(req, res) {
  //TODO add some custom logic for creating nonce
  let nonce = new IntegrityNonce("NzBCb1NkaE1lSWtaVXFGMk9uMzQ1NHZSS2s1UmFzRUhPWU5LU215WVFIdXBYM2o0VE0=")
  res.status(200).send(JSON.stringify(nonce));
}

async function tokenVerdict(req, res) {
  const { token = "none" } = req.query;
  //your server should already have nonce value, so ignore this in real implementation
  const { nonce = "none" } = req.query;

  if (token == "none") {
    res.status(400).send({ error: "No token provided" });
    return;
  }
  if (nonce == "none") {
    res.status(400).send({ error: "No nonce provided" });
    return;
  }

  decodeToken(token)
    .then((data) => {
      console.log(data)
      // let verdictResult = new VerdictResult(isIntegrityCompormised(data, nonce))
      res.status(200).send(JSON.stringify(data));
    })
    .catch((e) => {
      console.log(e);
      res.status(400).send({ error: "Google API error.\n" + e.message });
    });
}

async function decodeToken(token) {
  let jwtClient = new google.auth.JWT(
    privatekey.client_email,
    null,
    privatekey.private_key,
    ["https://www.googleapis.com/auth/playintegrity"]
  );

  google.options({ auth: jwtClient });

  const res = await playintegrity.v1.decodeIntegrityToken({
    packageName: packageName,
    requestBody: {
      integrityToken: token,
    },
  });

  return res.data.tokenPayloadExternal;
}

function isIntegrityCompormised(payload, nonce) {
  switch (false) {
    case isRequestDetailsValid(payload.requestDetails, nonce):
      console.log("Integrity request is compromised");
      return status.COMPROMISED;
    case isAppIntegrityValid(payload.appIntegrity):
      console.log("Application integrity is compromised");
      return status.COMPROMISED;
    case isDeviceIntegrityValid(payload.deviceIntegrity):
      console.log("Device integrity is compromised");
      return status.COMPROMISED;
    case isAppLicensingIntegrityValid(payload.accountDetails):
      console.log("Application licensing integrity is compromised");
      return status.COMPROMISED;
    default:
      return status.OK;
  }
}

function isRequestDetailsValid(details, nonce) {
  let currentTime = new Date().getTime();
  return (
    details.requestPackageName === packageName &&
    details.nonce === nonce &&
    currentTime - details.timestampMillis < ALLOWED_WINDOW_MILLIS
  );
}

function isAppIntegrityValid(appIntegrity) {
  return appIntegrity.appRecognitionVerdict === "PLAY_RECOGNIZED";
}

function isDeviceIntegrityValid(deviceIntegrity) {
  return deviceIntegrity.deviceRecognitionVerdict === "MEETS_DEVICE_INTEGRITY";
}

function isAppLicensingIntegrityValid(accountDetails) {
  return accountDetails.appLicensingVerdict === "LICENSED";
}

class VerdictResult{
  constructor(status){
    this.status = status
  }
}

class IntegrityNonce{
  constructor(nonce){
    this.nonce = nonce
  }
}

