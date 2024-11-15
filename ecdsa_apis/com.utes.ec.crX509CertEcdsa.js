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
var fs = require("fs");
var forge = require('node-forge');
var ecdsa = require('./com.utes.ec.x509.ecdsa');

/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
async
function crX509CertEcdsa() {
    console.log('Generating 2048-bit key-pair...');
    var keys = forge.pki.rsa.generateKeyPair(2048);
    console.log('Key-pair created.');
    var prvk = await
    ecdsa.crEcdsaKeys('private', 'pem');
    var pubk = await
    ecdsa.crEcdsaKeys('public', 'der');
    var ans1key = await
    ecdsa.crAns1Ecdsakeys();
    console.log('prvkey:  ' + prvk);
    console.log('pubkey:  ' + pubk);
    console.log('ans1key:  ' + ans1key);
    console.log('Creating self-signed certificate...');
    var cert = forge.pki.createCertificate();
    cert.publicKey = pubk;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter
	    .setFullYear(cert.validity.notBefore.getFullYear() + 1);
    var attrs = [ {
	name : 'commonName',
	value : 'example.org'
    }, {
	name : 'countryName',
	value : 'US'
    }, {
	shortName : 'ST',
	value : 'Virginia'
    }, {
	name : 'localityName',
	value : 'Blacksburg'
    }, {
	name : 'organizationName',
	value : 'Test'
    }, {
	shortName : 'OU',
	value : 'Test'
    } ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    /*
     * cert.setExtensions([{ name: 'basicConstraints', cA: true/*,
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
    // self-sign certificate
    // read :
    // https://security.stackexchange.com/questions/147803/how-are-ecdsa-signatures-computed-for-x509-certificates
    console.log('signingkey:  ' + ans1key);
    cert.sign(ans1key/* , forge.md.sha256.create() */);
    console.log('Certificate created.');

    // PEM-format keys and cert
    var pem = {
	privateKey : prvk,
	publicKey : pubk,
	certificate : forge.pki.certificateToPem(cert)
    };

    console.log('\nKey-Pair:');
    console.log(pem.privateKey);
    console.log(pem.publicKey);

    console.log('\nCertificate:');
    console.log(pem.certificate);

    // verify certificate
    var caStore = forge.pki.createCaStore();
    caStore.addCertificate(cert);
    try {
	forge.pki.verifyCertificateChain(caStore, [ cert ], function(vfd,
		depth, chain) {
	    if (vfd === true) {
		console.log('SubjectKeyIdentifier verified: '
			+ cert.verifySubjectKeyIdentifier());
		console.log('Certificate verified.');
	    }
	    return true;
	});
    } catch (ex) {
	console.log('Certificate verification failure: '
		+ JSON.stringify(ex, null, 2));
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
async
function callX509Cr() {
    await
    crX509CertEcdsa();
}

// https://security.stackexchange.com/questions/58077/generating-ecdsa-certificate-and-private-key-in-one-step
// async function crEcdsaSSL() {
// openssl ecparam -name secp521r1 -genkey -param_enc explicit -out
// private-key.pem
// openssl req -new -x509 -key private-key.pem -out server.pem -days 730
// }

exports.crX509CertEcdsa = crX509CertEcdsa;
exports.callX509Cr = callX509Cr;
callX509Cr();