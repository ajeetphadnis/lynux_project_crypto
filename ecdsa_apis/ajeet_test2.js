/**
 * Project: com.utes.cert.crypto
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */
// var jscert = require('js-x509-utils');
const { generateKeyPair } = require('crypto');
const jose = require('node-jose');
const fs = require('fs');
const {X509Certificate} = require('crypto');
var forge = require('node-forge');

var pubkey;
var prvkey;
var pemKey;



/**
 * This async function takes args : typStr : private / public key_path : private
 * key pem format - that is available for a user or damain in the database -
 * rsa_domain.
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function createKeystore(typStr, prvkey) {
    // prvKey = fs.readFileSync(path.join(key_path));
    const keystore = jose.JWK.createKeyStore();
    await keystore.add(prvkey, 'pem');     
    // await keystore.add(privkeys[0], 'pem');
    if (typStr==='private') {
	prvJk = await JSON.stringify(keystore.toJSON(true));
	console.log("ksprv:  " + prvJk);
	return prvJk;
    } else if (typStr ==='public') {
	pubJk = await JSON.stringify(keystore.toJSON());   
	console.log("kspub:  " + pubJk);
	return pubJk
    }
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function crEcdsaKeys(type) {
    return new Promise( function (resolve, reject) {
	if (resolve) {
            console.log("crEcdsaKeys001: " + type);
            generateKeyPair('ec', {
        	namedCurve: 'P-256',   // Options
        	publicKeyEncoding: {
        	    type: 'spki',
        	    // type: 'pkcs1',
        	    // format: 'der'
        	    format: 'pem'
        	},
        	privateKeyEncoding: {
        	    type: 'pkcs8',
        	    // type: 'pkcs1',
        	    // format: 'der'
        	    format: 'pem'
        		// cipher: 'aes-192-cbc',
        		// passphrase: 'Welcome to TutorialsPoint!'
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


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function getCert(type) {
    try {
        console.log("getCert001:  " + type);
        var ret = await crEcdsaKeys(type); // .then(pubkey => { console.log(
					    // pubkey )});
        console.log("getCert002:  " + ret);
	    ret = await crEcdsaKeys('private'); // .then(prvkey => {
						// console.log( prvkey )});
	    console.log("getCert003: " + ret);
         // return ret;
	} catch (ex) {
		if (ex.stack) {
		    console.log(ex.stack);
		} else	{
		    console.log('Error', ex);
		}
	}    
}


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async function crX509ECDSACert() {
    await getCert('public');
    await getCert('private');
    // display the result
    console.log("publickey :  " + pubkey);
    var pubTmp = pubkey;
    pubkey = pubkey.replace('-----BEGIN PUBLIC KEY-----', '-----BEGIN CERTIFICATE-----');
    pubkey = pubkey.replace('-----END PUBLIC KEY-----', '-----END CERTIFICATE-----');
    console.log("privatekey:  " + prvkey); // display the result
    var prvjk = await createKeystore('private', prvkey);
    var pubjk = await createKeystore('public', pubTmp);
    console.log("privatekey:  " + prvjk); // display the result
    const publicJwk = {kty: 'EC', crv: 'P-256', x: '...', y: '...'}; // public
									// key
									// to be
									// signed
    const privateJwk = {ktyp: 'EC', crv: 'P-256', x: '...', y: '...', d: '...'}; // private
										    // key

    const name = { // this is optional
	      countryName: 'JP',
	      stateOrProvinceName: 'Tokyo',
	      localityName: 'Chiyoda',
	      organizationName: 'example',
	      organizationalUnitName: 'Research',
	      commonName: 'example.com'
	    };

	// sign
    /*
     * jscert.fromJwk( publicJwk, privateJwk, 'pem', { signature:
     * 'ecdsa-with-sha256', // signature algorithm days: 365, // expired in days
     * issuer: name, // issuer subject: name // assume that issuer = subject,
     * i.e., self-signed certificate }, 'pem' // output signature is in PEM.
     * DER-encoded signature is available with 'der'. ).then( (cert) => { // now
     * you get the certificate in PEM string });
     */
    
 // getting object of a PEM encoded X509 Certificate.
    // const x509 = new X509Certificate(pubkey);
    var cert = await forge.pki.createCertificate();
    console.log("subject :- " + JSON.stringify(cert));
}

exports.crX509ECDSACert = crX509ECDSACert;
exports.getCert = getCert;
exports.crEcdsaKeys = crEcdsaKeys;
// exports.createJWKStore = createJWKStore;
crX509ECDSACert();
// createJWKStore ('./ajeet.key');
