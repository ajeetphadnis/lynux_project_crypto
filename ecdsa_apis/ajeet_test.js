/**
 * Project: com.utes.cert.crypto
 * 
 * Module:
 * 
 * Created On: openssl base ecdsa cert CA
 * https://www.erianna.com/ecdsa-certificate-authorities-and-certificates-with-openssl/
 * https://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/
 * https://community.buypass.com/t/k9jt30/create-a-certificate-with-ecdsa
 * https://www.golinuxcloud.com/openssl-generate-ecc-certificate/ ecdsa cert
 * decoder: https://certificatedecoder.dev/ This is good:
 * https://kjur.github.io/jsrsasign/tool/tool_asn1dumper.html
 * 
 * Good ECDSA MATH: https://github.com/Azero123/simple-js-ec-math
 * https://www.npmjs.com/package/simple-js-ec-math
 * https://eng.paxos.com/blockchain-101-foundational-math
 */    
var fs = require("fs");
const asn1 = require('asn1.js');
    const BN = require('bn.js');
    const crypto = require('crypto');
    const { Certificate } = require('crypto');
    var forge = require("node-forge");
    const { X509Certificate } = require('crypto');
    var ecdsa = require('./com.utes.ec.x509.ecdsa');
    var ecdsacsr = require('ecdsa-csr');
    const openssl = require('openssl-nodejs');
    
    var newclient = {
	    clientId: 'ajeet001',
	    clientPw: 'ajeet001',
	    commonName: 'ajeet.com',
	    countryName: 'NO',
	    ST: 'ajeetInc',
	    localityName: 'Oslo',
	    organizationName: 'Ajeet Inc',
	    OU: 'Ajeet Integration',
	    keySize: 'prime256v1',
	    passphrase: 'ajeet001',
	    p12FileName: 'ajeet001.p12'
	};

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
    function getSubSerialNr() {
	var sn = Math.floor(Math.random() * 900000);
	console.log("SN:  " + sn);
	var dt = new Date();
	mm = (dt.getMonth() + 1).toString().padStart(2, "0");
	dd   = dt.getDate().toString().padStart(2, "0");
	var sn =sn+'-'+mm+dd;
	console.log('snum:  ' + sn);
	return sn;
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
    function addDayToCurrentDate(days){
	    let currentDate = new Date()
	    return new Date(currentDate.setDate(currentDate.getDate() + days))
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
    async function crCertCrypto2() {
	await getCert('private');
	console.log("prvkey_sign: " + prvkey);
	var domains = [ 'www.example.org', 'www.example.org','www.example.com', 'api.example.com' ];
	 
	return ecdsacsr({ key: prvkey, domains: domains }).then(function (csr) {
	    // csr = csr.toString('base64').match(/.{0,64}/g);
	    csr.version = 3;
	    csr.CN = 'Ajeet.com';
	    csr = csr.replace(/^\s*[\r\n]/gm, '');
	    csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----', '-----BEGIN CERTIFICATE-----');
	    csr = csr.replace('-----END CERTIFICATE REQUEST-----', '-----END CERTIFICATE-----');
	  console.log('CSR PEM:');
	  console.log(csr.toString('base64'));
	  var cert = csr.toString('base64');
	  // verifyX509Cert(prvkey);
	// getting object of a PEM encoded X509 Certificate.
// const x509 = new X509Certificate(fs.readFileSync('jwks/ajeet_test.pem'));
// console.log("x509: " + x509);
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
    async function verifyX509Cert(certStr) {	
// openssl(['req', '-text', '-noout' ,'-verify' ,'-in' ,'jwks/ajeet_test.pem'],
// function (err, buffer) {
// console.log(err.toString(), buffer.toString());
// });
// openssl(['x509', '-in', './jwks/ajeet_test.pem' ,'-text'], function (err,
// buffer) {
// console.log(err.toString(), buffer.toString());
// });
	
	openssl(['req', '-new', '-x509', '-key', certStr, '-out', 'certificate.pem', '-days', '900000', '-subj', '/C=PL/ST=Silesia/L=Katowice/O=MyOrganization/CN=CommonName'], function (err, buffer) {
	    console.log(err.toString(), buffer.toString());
	});

    }
    
/*
 * PEM is just a Base64-encoded DER (think JSON as hex or base64) DER is an
 * binary object notation for ASN.1 (think actual stringified JSON or XML) ASN.1
 * is object notation standard (think JSON, the standard) X.509 is a suite of
 * schemas (think XLST or json-schema.org) PKCS#8, PKIK, SPKI are all X.509
 * schemas (think defining firstName vs first_name vs firstname)
 */
    
    /**
     * 
     * 
     * 
     * 
     * @param firstname
     * @returns
     * 
     */
    async function crCertCrypto() {
	const cert1 = new Certificate();
	const cert2 = Certificate();
	console.log("Cert:   " + JSON.stringify(cert2));

	await getCert('private');
	console.log("prvkey_sign: " + prvkey);
	var sha256 = crypto.createHash("sha256");
	var sign = await crypto.createSign('sha512');
	    await sign.update(cert1.toString());
	    var signature = await sign.sign(prvkey, 'hex');
	    console.log('signature_cert:   ', signature);
	    console.log('signed_cert:    ', cert1);

	  const verify = crypto.createVerify('SHA256');
	  verify.write(cert1.toString());
	  verify.end();
	  console.log(verify.verify(pubkey, signature, 'hex'));	  
	  // Prints: true
	  var prefix = '-----BEGIN CERTIFICATE-----\n\r';
	  var postfix = '-----END CERTIFICATE-----';
	  var cert = prefix+cert1+'\n\r'+postfix+'\n\r';
	  console.log("cert 509: " + cert);
	  const x509 = new crypto.X509Certificate(cert);

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
    const EcdsaDerSig = asn1.define('ECPrivateKey', function() {
        return this.seq().obj(
            this.key('r').int(),
            this.key('s').int()
        );
    });
   
    
    /**
     * 
     * 
     * 
     * 
     * @param firstname
     * @returns
     * 
     */
    function asn1SigSigToConcatSig(asn1SigBuffer) {
        const rsSig = EcdsaDerSig.decode(asn1SigBuffer, 'der');
        return Buffer.concat([
            rsSig.r.toArrayLike(Buffer, 'be', 32),
            rsSig.s.toArrayLike(Buffer, 'be', 32)
        ]);
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
    function concatSigToAsn1SigSig(concatSigBuffer) {
        const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be');
        const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be');
        return EcdsaDerSig.encode({r, s}, 'der');
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
    function ecdsaSign(hashBuffer, key) {
        const sign = crypto.createSign('sha256');
        sign.update(asBuffer(hashBuffer));
        const asn1SigBuffer = sign.sign(key, 'buffer');
        return asn1SigSigToConcatSig(asn1SigBuffer);
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
    function ecdsaVerify(data, signature, key) {
        const verify = crypto.createVerify('SHA256');
        verify.update(data);
        const asn1sig = concatSigToAsn1Sig(signature);
        return verify.verify(key, new Buffer(asn1sig, 'hex'));
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
	        pubkey = await ecdsa.crEcdsaKeys('public', 'der'); // .then(pubkey
								    // => {
								    // console.log(
								    // // pubkey
								    // )});
	        console.log("getCert0002:  " + pubkey);
	        prvkey = await ecdsa.crEcdsaKeys('private', 'pem'); // .then(prvkey
								    // => {
		console.log("getCert0003:  " + prvkey);// console.log( prvkey
							// )});
	         // return ret;
		} catch (ex) {
			if (ex.stack) {
			    console.log(ex.stack);
			} else	{
			    console.log('Error', ex);
			}
		}    
	}
    
    
    /*
     * Using Nodejs crypto module:
     * https://nodejs.org/en/knowledge/cryptography/how-to-use-crypto-module/
     */
    /**
     * 
     * 
     * 
     * 
     * @param firstname
     * @returns
     * 
     */
    async function testEcdsaSign(type) {
	await getCert(type);
	console.log("prvkey: " + prvkey);
	var sha256 = crypto.createHash("sha256");
	console.log("hash: " + JSON.stringify(sha256));
	var dig = sha256.update("Hello World").digest('hex');
	console.log("digest: " + dig);

    }
    
    /*
     * Using Nodejs crypto module:
     * https://nodejs.org/en/knowledge/cryptography/how-to-use-crypto-module/
     */
   
    /**
     * 
     * 
     * 
     * 
     * @param firstname
     * @returns
     * 
     */
    async function testEcdsaSign(type, clientData, cacert, algType, req, res, next) {
	await getCert(type);
	console.log("prvkey: " + prvkey);
	var snr = getSubSerialNr();
        var nbf = new Date();
        var nafdate = addDayToCurrentDate(1);
	var cert = new crypto.Certificate();
	cert.verion = '3';
	cert.algorithm = 'P-256';
	cert.publicKey = pubkey;
        cert.serialNumber = snr;
        cert.notBefore = nbf;
        cert.notAfter = nafdate;
    	var data = JSON.stringify(clientData);
	JSON.parse(data, (key, value) => {
		  if (typeof value === 'string') {
		    // console.log("key: " + key);
		    if(key === 'clientId') newclient.clientId = value;
		    if(key === 'clientPw') newclient.clientPw = value;
		    if(key === 'commonName') newclient.commonName = value;
		    if(key === 'countryName') newclient.countryName = value;
		    if(key === 'ST') newclient.ST = value;
		    if(key === 'localityName') newclient.localityName = value;
		    if(key === 'organizationName') newclient.organizationName = value;
		    if(key === 'OU') newclient.OU = value;
		    if(key === 'keySize') newclient.keySize = value;
		    if(key === 'passphrase') newclient.passphrase = value;
		    if(key === 'p12FileName') newclient.p12FileName = value;
		  }
	});
        console.log('dates: nbf: ' + nbf + '   nafdate:   ' + nafdate);
	    var attrs_issuer = [
		{
		    name : 'commonName',
		    value : 'prathamesh-phadnis.com/subca-domain'
		},
		{
		    name : 'countryName',
		    value : 'NO'
		},
		{
		    shortName : 'ST',
		    value : 'Akerhusa'
		},
		{
		    name : 'localityName',
		    value : 'Oslo'
		},
		{
		    name : 'organizationName',
		    value : 'PrathamPhadnis_SUB_CA_TRUST_DOMAIN Inc'
		},
		{
		    shortName : 'OU',
		    value : 'SUB_CA_TRUST_DOMAIN CryptoApps'
		} ];

	    var attrs_subject = [
		{
		    name : 'commonName',
		    value : newclient.commonName
		},
		{
		    name : 'countryName',
		    value : newclient.countryName
		},
		{
		    shortName : 'ST',
		    value : newclient.ST
		},
		{
		    name : 'localityName',
		    value : newclient.localityName
		},
		{
		    name : 'organizationName',
		    value : newclient.organizationName
		},
		{
		    shortName : 'OU',
		    value : newclient.OU
		} ];

	    cert.subject = attrs_subject;
	    cert.issuer = attrs_issuer;
	 // self-sign certificate
	    console.log("privatekey:  " + prvkey);
	    var sign = await crypto.createSign('sha512');
	    await sign.update(cert.toString());
	    var signature = await sign.sign(prvkey, 'hex');
	    console.log('signature_cert:   ', signature);
	    console.log('signed_cert:    ', cert);
	    
	    var prefix = '-----BEGIN CERTIFICATE-----\n\r';
	    var postfix = '-----END CERTIFICATE-----';
	    var cert = prefix+cert+'\n\r'+postfix;
	    console.log("cert 509: " + cert.toString('base64'));
	    var derKey = forge.util.decode64(cert.toString('base64'));
		var asnObj = forge.asn1.fromDer(derKey);
		var asn1Cert = forge.pki.certificateFromAsn1(asnObj);
		return forge.pki.certificateToPem(asn1Cert);
	    // const x509 = new crypto.X509Certificate(cert.toString());
	    // console.log("cert: " + x509);

    }
    
    
    // testEcdsaSign('private');
    // crCertCrypto();
    // crCertCrypto2();
    testEcdsaSign('private', newclient, '', 'secp521r1', '', '', '');