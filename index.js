const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const request = require("request");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const Validator = require('jsonschema').Validator;
const dotEnvConfig = process.env.PORT === '4000' ? { path: '.env2' } : { silent: true };
require("dotenv").config(dotEnvConfig);

const app = express();

app.use(require("body-parser").json());

// create application/x-www-form-urlencoded parser
var urlencodedParser = require("body-parser").urlencoded({ extended: false })

app.use(express.static("public"));

app.use((req, res, next) => {
    const proto = req.headers["x-forwarded-proto"];
    if (proto && proto !== "https") {
        return res.redirect(302, `https://${req.hostname}${req.originalUrl}`);
    }

    return next();
});

app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    next();
});

const FileStore = require("session-file-store")(session);
app.use(
    session({
        store: new FileStore(),
        secret: process.env.JWT_SECRET,
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: { secure: process.env.NON_SECURE_SESSION !== "true" },
    })
    );

app.set("view engine", "jade");

const isJson = (str) => {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
const valid = new Validator();
const discoverySchema = {
    "type": "object",
    "properties": {
      "authorization_endpoint": {"type": "string"},
      "token_endpoint": {"type": "string"},
      "jwks_uri": {"type": "string"},
    },
    "required": ["authorization_endpoint","token_endpoint","jwks_uri"]
  };

app.get("/discover", (req, res) => {
    console.log(req.query.url);
    request.get(req.query.url, (err, resp, body) => {
        if (err) {
            return res.send(err);
        } else {
            if (isJson(body)) {
                const isValid = valid.validate(JSON.parse(body), discoverySchema);
                if (isValid.errors.length < 1) {
                    return res.send(body);
                } else {
                    return res.status(400).json({"message":"Discovery document is not valid", "errors": isValid.errors.map(e => e.message)});
                }
            } else {
                return res.status(400).json({"message": "Discovery document is not a JSON file."});
            }
        }
    });
});

app.get("/callback", (req, res) => {
    if (req.query.code) {
        /* eslint-disable no-param-reassign */
        req.session.refresh = false;
        req.session.authCode = req.query.code;
        /* eslint-enable no-param-reassign */
        res.redirect("/");
    }
});

app.get("/logout", (req, res) => {
    console.log(req.query.id_token_hint || null);
    console.log(req.query.client_id || null);
    var url = `${process.env.LOGOUT_URI}?id_token_hint=${req.query.id_token_hint || null}&client_id=${req.query.client_id || null}`;
    request.get(url, (err, resp, body) => {
        console.log(resp.status, body);
        res.json(body);
    });
});

app.post('/backchannel_logout',urlencodedParser, (req, res) => {
    console.log('backchannel_logout has been called');
    console.log(req.urlencoded);
    console.log(req.body);
    console.log(req.headers);
    res.status(200).send("");
});

app.get('/backchannel_exchange',urlencodedParser, (req, res) => {

    // Prepare the request payload
    const requestData = {
        client_id: process.env.EXCHANGE_CLIENT_ID,
        client_secret: process.env.EXCHANGE_CLIENT_SECRET,
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: req.query.token,
        subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
        requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
        scope: "openid digital_identity_id email",
    };

    // Make the POST request
    request.post(
      {
          url: process.env.TOKEN_URI,
          headers: {
              "Content-Type": "application/x-www-form-urlencoded",
          },
          form: requestData,
      },
      (error, response, body) => {
          if (error) {
              console.error("Error during token exchange:", error);
              return;
          }

          // Parse the response
          if (response.statusCode === 200) {
              const parsedBody = JSON.parse(body);
              console.log("Token exchange successful:", parsedBody);
          } else {
              console.error(
                "Token exchange failed:",
                `Status Code: ${response.statusCode}, Body: ${body}`,
                response.headers
              );
          }
      }
    );
});


app.get("*", (req, res) => {
    let code = null;
    if (!req.session.refresh && req.session.authCode) {
        code = req.session.authCode;
        /* eslint-disable no-param-reassign */
        req.session.refresh = true;
        /* eslint-enable no-param-reassign */
    }
    res.render("index", {
        code,
        redirect_uri: process.env.REDIRECT_URI,
        state: crypto.randomBytes(20).toString("hex"),
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
    });
});

app.post("/code_to_token", (req, res) => {
    // REQUIRED params: code, clientID, clientSecret, tokenEndpoint, serviceURL
    // step 1: exchange code for token with OIDC server
    // step 2: send back https response from OIDC server
    const result = {};
    const reqData = {
        code: req.body.code,
        client_id: req.body.clientID,
        client_secret: req.body.clientSecret,
        grant_type: "authorization_code",
        redirect_uri: process.env.REDIRECT_URI,
    };

    request.post(
        req.body.tokenEndpoint, {
            form: reqData,
        },
        (err, response, body) => {
            console.log(JSON.stringify(response.headers));
            result.body = body;
            result.response = response;
            // and add the decoded token
            result.decodedToken = JSON.stringify(
                jwt.decode(result.id_token, { complete: true })
            );
            res.json(result);
        }
    );
});

app.post("/validate", (req, res) => {
    if (!req.body.idToken) {
        return res.status(400).send("Missing idToken param.");
    }

    const tokenHeader = jwt.decode(req.body.idToken, { complete: true }).header;

    // RS256 = validation with public key
    if (tokenHeader.alg === "RS256") {
        if (!req.body.tokenKeysEndpoint) {
            return res
                .status(400)
                .send(
                    `idToken algorithm is ${tokenHeader.alg} but tokenKeysEndpoint param is missing.`
                );
        }
        if (!tokenHeader.kid) {
            return res
                .status(400)
                .send(
                    `idToken algorithm is ${tokenHeader.alg} but kid header is missing.`
                );
        }

        // fetch public key
        return request.get({
                url: req.body.tokenKeysEndpoint,
                json: true,
            },
            (err, resp, body) => {
                // find key with matching kid
                if (!body || !body.keys || !Array.isArray(body.keys)) {
                    return res
                        .status(400)
                        .send(`No public key found with matching kid '${tokenHeader.kid}'`);
                }

                const key = body.keys.find((k) => k.kid === tokenHeader.kid);
                if (!key) {
                    return res
                        .status(400)
                        .send(`No public key found with matching kid '${tokenHeader.kid}'`);
                }

                const secret = jwkToPem(key);
                return verify(secret);
            }
        );
        // HS256 = validation with client secret
    } else if (tokenHeader.alg === "HS256") {
        if (!req.body.clientSecret) {
            return res
                .status(400)
                .send(
                    `idToken algorithm is ${tokenHeader.alg} but clientSecret param is missing.`
                );
        }

        const secret =
            req.body.server === "Auth0" ?
            new Buffer(req.body.clientSecret, "base64") :
            req.body.clientSecret;
        return verify(secret);
    }
    return res
        .status(400)
        .send(`Unsupported idToken algorithm: ${tokenHeader.alg}`);

    function verify(secret) {
        jwt.verify(req.body.idToken, secret, (err, decoded) => {
            if (err) {
                return res.status(400).send(err);
            }

            return res.json(decoded);
        });
    }
});

app.listen(process.env.PORT || 3000);
