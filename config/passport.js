// load all the things we need
var LocalStrategy = require('passport-local').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;

// load up the user model
var User = require('../app/models/users');

// load the auth variables
var configAuth = require('./auth');
var jsSHA = require("jssha");
const crypto = require('crypto');
const secp256k1 = require('secp256k1');
// load the fetch
const fetch = require('node-fetch');


// expose this function to our app using module.exports
module.exports = function (passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================

    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });
    // used to deserialize the user
    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            done(err, user);
        });
    });


    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    }, async (req, email, password, done) => {
        // asynchronous
        // User.findOne wont fire unless data is sent back

            // find a user whose email is the same as the forms email
            // we are checking to see if the user trying to login already exists
            const user = await User.findOne({'local.email': email});
                // if there are any errors, return the error


                // check to see if theres already a user with that email
                if (user) {
                    return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                } else {
                    // if there is no user with that email
                    // create the user
                    var newUser = new User();

                    // set the user's local credentials
                    newUser.local.email = email;
                    newUser.local.password = newUser.generateHash(password);

                    await newUser.save();
                    return done(null, newUser);

                }

    }));


    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    }, async (req, email, password, done) => {
        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        const user = await User.findOne({'local.email': email});
            // if there are any errors, return the error before anything else
            console.log('Req: IP --> ',req.ip);
            // console.log('Req: --> ',req);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // Add 2FA Code here
            // fetch('https://api.ix-security.com/api/authentications/request')
            // .then(res => res.text())
            // .then(body => console.log(body));
            const sample_data = {
              field1: 'str',
              field2: 1,
              field3: true
            };
            const auth_info = {
              account: email,
              timestamp: Math.trunc(Date.now()/1000),
              // challenge: '1a2b',
              challenge: 'jiVnc6u1ax',
              msg: 'Hello',
              options: ['YES','NO'],
              payload: JSON.stringify(sample_data)
            };
            var shaObj = new jsSHA("SHA-1", "TEXT");
            shaObj.setHMACKey(configAuth.trioSkey, "TEXT");
            shaObj.update(JSON.stringify(auth_info));
            var hmac = shaObj.getHMAC("HEX");
            const auth_request = {
              signature: hmac,
              data: auth_info
            };
            const body =
            {
              version: 'v3',
              id: configAuth.trioIkey,
              auth_req: JSON.stringify(auth_request)
            };

            console.log(body);

            fetch('https://api.ix-security.com/api/authentications/request', {
              method: 'post',
              body:    JSON.stringify(body),
              headers: { 'Content-Type': 'application/json' },
            })
            .then(res => res.json())
            .then(json => {
              console.log('Response -> ');
              console.log(json);
              const msg = Buffer.from('1a2b:YES','utf8');
              console.log(msg);
              const hashedmsg = crypto.createHash('sha256').update(msg).digest();
              console.log(hashedmsg);
              const hashMsg = sha256(hashedmsg);
              console.log(hashMsg);

              const keyBuf = Buffer.from(json.auth_response.data.key,'hex');
              console.log(json.auth_response.data.extraAck);
              let signatureBuffer = Buffer.from(json.auth_response.data.extraAck, 'hex');
              // console.log(signatureBufferDER);
              // let signatureBuffer = secp256k1.signatureImport(signatureBufferDER);
              let normalizedSigBuf = secp256k1.signatureNormalize(signatureBuffer);
              console.log('Normalized Signature:', normalizedSigBuf);
              console.log(secp256k1.verify(hashMsg, normalizedSigBuf, keyBuf));
              // if (!json.auth_response.data.message)
                // return done(null, false, req.flash('loginMessage', 'Oops! 2FA not Successful.')); // Success: false from 2FA
              return done(null, user);
            })
            .catch(err => {
              if (err)
              {
                console.error('Catch Exception: -- ' + err);
                done(null, false, req.flash('loginMessage', 'Exception Error - Maybe Timeout'));
              }
            });

            // all is well, return successful user
            // return done(null, user);


    }));

    var sha256 = function(buffer) {
        var f = crypto.createHash("SHA256");
        var h = f.update(buffer);
        return h.digest();
    };

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================










};
