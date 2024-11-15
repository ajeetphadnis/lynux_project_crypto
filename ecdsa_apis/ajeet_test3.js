'use strict';
const { generateKeyPair } = require('crypto');
const jose = require('node-jose');
const fs = require('fs');
const jwt = require('jsonwebtoken');



var pubkey;
var prvkey;
var pemKey;


async function crEcdsaKeys(type) {
    return new Promise( function (resolve, reject) {
	if (resolve) {
            console.log("crEcdsaKeys001: " + type);
            generateKeyPair('ec', {
        	namedCurve: 'P-256',   // Options
        	publicKeyEncoding: {
        	    type: 'spki',
        	    //type: 'pkcs1',
        	    //format: 'der'
        	    format: 'pem'
        	},
        	privateKeyEncoding: {
        	    type: 'pkcs8',
        	    //type: 'pkcs1',
        	    //format: 'der'
        	    format: 'pem'
        		//cipher: 'aes-192-cbc',
        		//passphrase: 'Welcome to TutorialsPoint!'
        	}
            },
            (err, publicKey, privateKey) => { // Callback function
        	// console.log("crEcdsaKeys002: "+ privateKey);
        	// return Promise.resolve(privateKey);
        	if(!err) {
        	    // Prints new asymmetric key
        	    // pair after encoding
        	    if (type === 'public') {
        		pubkey = publicKey.toString('hex');
        		console.log("crEcdsaKeys003: ",  pubkey);
        		// return Promise.resolve(pubkey);
        		resolve(pubkey);
        	    }
        	    if (type === 'private') {
        		// console.log("Private Key is: ",
    			// privateKey.toString('hex'));
        		prvkey = privateKey.toString('hex');
        		console.log("crEcdsaKeys004: " + prvkey);        		
    	               resolve(pubkey);
    	           }    	           
        	}
            })
	}  else if (reject) {
	    console.log("crEcdsaKeys009: ");
	    // Prints error
	    console.log("Errr is: ", err);
	}
    });
}

async function getCert(type) {
    try {
        console.log("getCert001:  " + type);
        var ret = await crEcdsaKeys('public'); // .then(pubkey => { console.log(
					    // pubkey )});
        console.log("getCert002:  " + ret);
	    ret = await crEcdsaKeys('private'); // .then(prvkey => {
						// console.log( prvkey )});
	    var csr = await crEcdsaToken('private');
	    console.log("Token:  " + JSON.stringify(csr));
	    console.log("getCert003: " + csr);
         // return ret;
	} catch (ex) {
		if (ex.stack) {
		    console.log(ex.stack);
		} else	{
		    console.log('Error', ex);
		}
	}    
}
var domains = [ 'example.com', 'www.example.com', 'api.example.com' ];

async function crEcdsaToken(type) {
    //await getCert('private');
    const payload = {
	    cert_hash: 'whatever'
	  }
	  const signOptions = {
	    algorithm: "ES256",
	    expiresIn: Math.floor(Date.now() / 1000) + 1800,
	    issuer: 'whatever',
	    subject: 'whatever'
	  }

	  return jwt.sign(payload, prvkey, signOptions);
}


exports.getCert = getCert;
exports.crEcdsaKeys = crEcdsaKeys;
exports.crEcdsaToken = crEcdsaToken;

getCert('private');
