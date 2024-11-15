/**
 * Project: com.utes.cert.crypto
 * 
 * Module:
 * 
 * Created On: Based on : https://asecuritysite.com/encryption/js_ecdh Node.js
 * has an in-built crypto module and which can be used to run code using
 * Javascript. This example implements the Elliptic Curve Diffie Hellman (ECDH)
 * key exchange method. x509 does not recommend brainpool algs from TLS 1.3 And
 * hence this implementation is omitting brainpool algs. Benifits of Elliptic
 * curve algs: https://www.digicert.com/faq/ecc.htm To run : node
 * sample_node/com.utes.ec.x509.sect571r1 Type: secp128r2, brainpoolP512r1 or
 * any other alg
 * https://stackoverflow.com/questions/51046309/crypto-how-to-generate-ecdh-pem
 * https://www.instructables.com/Understanding-how-ECDSA-protects-your-data/
 * https://github.com/indutny/elliptic/
 */
var fs = require("fs");
var forge = require('node-forge');
var jose = require('node-jose');
// ecdsa impl function

var crypto = require("crypto");
const { generateKeyPair } = require('crypto');
var asn1 = require('asn1.js');
var BN = require('bn.js');
var pubkey;
var prvkey;
var pemKey;


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
function toOIDArray(oid) {
    return oid.split('.').map(function(s) {
      return parseInt(s, 10)
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
function crAns1Ecdsakeys() {
    // Define ECPrivateKey from RFC 5915
       var ECPrivateKey = asn1.define('ECPrivateKey', function() {
         this.seq().obj(
           this.key('version').int(),
           this.key('privateKey').octstr(),
           this.key('parameters').explicit(0).objid().optional(),
           this.key('publicKey').explicit(1).bitstr().optional()
         );
       });

       // Generate the PEM-encoded private key
       pemKey = ECPrivateKey.encode({
         version: new BN(1),
         privateKey: prvkey,
         // OID for brainpoolP512t1
         // parameters: toOIDArray('1.3.36.3.3.2.8.1.1.14')
         parameters: toOIDArray('1.2.840.10045.3.1.7')
       }, 'pem', { label: 'EC PRIVATE KEY' });

       console.log("privatekey:  " + pemKey);
       return pemKey;
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
function crAns1Eckeys() {
 // Define ECPrivateKey from RFC 5915
    var ECPrivateKey = asn1.define('ECPrivateKey', function() {
      this.seq().obj(
        this.key('version').int(),
        this.key('privateKey').octstr(),
        this.key('parameters').explicit(0).objid().optional(),
        this.key('publicKey').explicit(1).bitstr().optional()
      );
    });

    // Generate the DH keys
    // var ecdh = crypto.createECDH('brainpoolP512t1');
    var ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    // Generate the PEM-encoded private key
    pemKey = ECPrivateKey.encode({
      version: new BN(1),
      privateKey: ecdh.getPrivateKey(),
      // OID for brainpoolP512t1
      // parameters: toOIDArray('1.3.36.3.3.2.8.1.1.14')
      parameters: toOIDArray('1.2.840.10045.3.1.7')
    }, 'pem', { label: 'EC PRIVATE KEY' });

    console.log("privatekey:  " + pemKey);
    return pemKey;
    // Sign data
// var sign = crypto.createSign('sha512');
// sign.update('Test this data for verify method');
// var signature = sign.sign(pemKey, 'hex');
//
// console.log('signature', signature);
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
async function crEcdsaKeys(type, format) {
    return new Promise( function (resolve, reject) {
	if (resolve) {
            console.log("crEcdsaKeys001: " + type);
            generateKeyPair('ec', {
        	namedCurve: 'prime256v1',   // Options
        	publicKeyEncoding: {
        	    type: 'spki',
        	    // format: 'der'
        	    // format: 'pem'
        	    format: format
        	},
        	privateKeyEncoding: {
        	    type: 'pkcs8',
        	    // format: 'der'
        	    // format: 'pem'
        	    format: format
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
        		// Sign data
// var sign = crypto.createSign('sha512');
// sign.update('Test this data for verify method');
// var signature = sign.sign(prvkey, 'hex');
// console.log('signature', signature);
    	               resolve(prvkey);
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
    async function crEcdhKeys() {
        var eccrypto = require("eccrypto");
    
        var privateKeyA = eccrypto.generatePrivate();
        var publicKeyA = eccrypto.getPublic(privateKeyA);
        var privateKeyB = eccrypto.generatePrivate();
        var publicKeyB = eccrypto.getPublic(privateKeyB);
    
        eccrypto.derive(privateKeyA, publicKeyB).then(function(sharedKey1) {
          eccrypto.derive(privateKeyB, publicKeyA).then(function(sharedKey2) {
            console.log("Both shared keys are equal:", sharedKey1, sharedKey2);
          });
        });
    }

// end ecdsa


    
    /**
     * 
     * 
     * 
     * 
     * @param firstname
     * @returns
     * 
     */
async function crX509CertEcc (type) {
    console.log('Generating 2048-bit key-pair...');
    // var keys = await forge.pki.rsa.generateKeyPair(2048);
    console.log('Key-pair created.');
    // crAns1Eckeys();
    console.log('Creating self-signed certificate...   ' );
    var cert = await forge.pki.createCertificate();
    cert.publicKey = pubkey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    var attrs = [{
      name: 'commonName',
      value: 'example.org'
    }, {
      name: 'countryName',
      value: 'US'
    }, {
      shortName: 'ST',
      value: 'Virginia'
    }, {
      name: 'localityName',
      value: 'Blacksburg'
    }, {
      name: 'organizationName',
      value: 'Test'
    }, {
      shortName: 'OU',
      value: 'Test'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    /**
     * cert.setExtensions([{ name: 'basicConstraints', cA: true/* ,
     * pathLenConstraint: 4 }, { name: 'keyUsage', keyCertSign: true,
     * digitalSignature: true, nonRepudiation: true, keyEncipherment: true,
     * dataEncipherment: true }, { name: 'extKeyUsage', serverAuth: true,
     * clientAuth: true, codeSigning: true, emailProtection: true, timeStamping:
     * true }, { name: 'nsCertType', client: true, server: true, email: true,
     * objsign: true, sslCA: true, emailCA: true, objCA: true }, { name:
     * 'subjectAltName', altNames: [{ type: 6, // URI value:
     * 'http://example.org/webid#me' }, { type: 7, // IP ip: '127.0.0.1' }] }, {
     * name: 'subjectKeyIdentifier' }]);
     */
    // FIXME: add authorityKeyIdentifier extension
    console.log('unsigned_cert:    ', cert);
    // var cert_pem = forge.pki.certificateToPem(cert);
    
    // self-sign certificate
    console.log("privatekey:  " + prvkey);
    var sign = await crypto.createSign('sha512');
    await sign.update(cert.toString());
    var signature = await sign.sign(prvkey, 'hex');
    console.log('signature_cert:   ', signature);
    console.log('signed_cert:    ', cert);
    
    
    // PEM-format keys and cert
     var pem = {
     // privateKey: forge.pki.privateKeyToPem(keys.privateKey),
     privateKey: prvkey,
     publicKey: pubkey,
     // publicKey: forge.pki.publicKeyToPem(keys.publicKey),
     certificate: cert
     };
        
     console.log('\nKey-Pair:');
     console.log(pem.privateKey);
     console.log(pem.publicKey);
    
     console.log('\nCertificate:' + JSON.stringify(cert));
     console.log(pem.certificate);
    
    // verify certificate
    var caStore = forge.pki.createCaStore();
    caStore.addCertificate(cert);
    try {
      forge.pki.verifyCertificateChain(caStore, [cert],
        function(vfd, depth, chain) {
          if(vfd === true) {
            console.log('SubjectKeyIdentifier verified: ' +
              cert.verifySubjectKeyIdentifier());
            console.log('Certificate verified.');
          }
          return true;
      });
    } catch(ex) {
      console.log('Certificate verification failure: ' +
        JSON.stringify(ex, null, 2));
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
    async function getECPubkey(type) {
	try {
            var pubk = await crEcdsaKeys('public');
            console.log("getECPubkey001:  " + pubk)
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
 async function getCert(type, format) {
        try {
            console.log("getCert001:  " + type);
            var ret = await crEcdsaKeys(type, format); // .then(pubkey => {
						// console.log( pubkey )});
            console.log("getCert002:  " + ret);
    	    ret = await crEcdsaKeys('private', format); // .then(prvkey => {
						// console.log( prvkey )});
    	    console.log("getCert003: " + ret);
    	    // await crX509CertEcc(type);
    	    var ans1key = crAns1Ecdsakeys();
             // return ret;
    	} catch (ex) {
    		if (ex.stack) {
    		    console.log(ex.stack);
    		} else	{
    		    console.log('Error', ex);
    		}
    	}    
    }
    

exports.pubkey = pubkey;
exports.prvkey = prvkey;
exports.crX509CertEcc = crX509CertEcc;
exports.crEcdhKeys = crEcdhKeys;
exports.crEcdsaKeys = crEcdsaKeys;
exports.getCert = getCert;
exports.crAns1Eckeys = crAns1Eckeys;
exports.crAns1Ecdsakeys = crAns1Ecdsakeys;

// crEcdsaKeys('private');
// crEcdhKeys();
getCert('public', 'pem');
// console.log("main001: " + ree );
// crAns1Eckeys();
