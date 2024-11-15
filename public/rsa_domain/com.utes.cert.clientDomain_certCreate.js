/**
 * http://usejsdoc.org/ This file creates client domain cert chain
 */

// http://ospkibook.sourceforge.net/docs/OSPKI-2.4.7/OSPKI-html/sample-ca-cert-txt.htm
// https://github.com/ThauEx/ffrk-proxy/blob/master/tests/createRootCa.js
// https://github.com/ThauEx/ffrk-proxy/blob/master/lib/cert.js
// http://www.steves-internet-guide.com/ssl-certificates-explained/
/*
 * Second in the chain (TrustedSecureCertificateAuthority5.crt). Note: Subject
 * is equal to previous file’s Issuer : Issuer (ROOT CA) : C=US, ST=New Jersey,
 * L=Jersey City, O=The USERTRUST Network, CN=USERTrust RSA Certification
 * Authority Subject: C=US, ST=DE, L=Wilmington, O=Corporation Service Company,
 * CN=Trusted Secure Certificate Authority 5
 * To get authorityKeyIdentifier: https://github.com/digitalbazaar/forge/issues/462
 */
// iOS - requires p12 with :
// iOS apparently requires a TripleDES encryption algorithm. So I was able to fix my code by doing
// var p12Asn1 = forge.pkcs12.toPkcs12Asn1(asn1Cert.privateKey , [asn1Cert.rawCert], "iPhone", {algorithm : '3des'});

global.clientdata;
var forge = require('node-forge');
var fs = require('fs');
var secureRandom1 = require('secure-random');
var secureRandom = require('../rsa_utils/rsa_utilfunctions');
const Clients = require("../models/com.utes.cert.clients");
var clientDb = require('../models/com.utes.mongo.certClient.crud');
var newclient = new Clients ({
    clientId:String,
    clientPw:String,
    commonName:String,
    countryName:String,
    ST:String,
    localityName:String,
    organizationName:String,
    OU:String,
    keySize:String,
    passphrase:String,
    p12FileName:String
});

var certSN;

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

function getHexSerialNr(length) {
    const genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    var hx = genRanHex(length);
    //hx = hx.replace(/..\B/g, '$&:');
    return hx;
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
  }

function createP12RSA_CLIENT_DOMAIN_TRUST_Cert(clientData, text, req, res, next) {
    try	{
	// test if the client data is available
    	// gen 6 digit random
    	certSN = getHexSerialNr(16);
    	console.log("getHexSerialNr: " + certSN);
    	console.log("clientData: " + JSON.stringify(clientData));
    	var data = JSON.stringify(clientData);
	JSON.parse(data, (key, value) => {
		  if (typeof value === 'string') {
		    //console.log("key:  " + key);
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
	    // generate a keypair
	    console.log('Generating 4096-bit RSA_CLIENT_DOMAIN_TRUST_Cert - key-pair...');
	    var ksize;
	    if (newclient.keySize === '1024') {
		ksize = 1024;
	    } else if (newclient.keySize === '2048') {
		ksize = 2048;
	    } 
	    
	    var keys = forge.pki.rsa.generateKeyPair(ksize);
	    console.log('RSA_CLIENT_DOMAIN_TRUST_Cert Key-pair created.');
	    // create random serial no
	    // var bytes = secureRandom(10, {type: 'Buffer'}) //return a Buffer
	    // of 10 bytes
	    // console.log(bytes.length) //10

	    // create a certificate
	    console.log('Creating RSA_CLIENT_DOMAIN_TRUST_Cert certificate...');
	    var cert = forge.pki.createCertificate();
	    cert.publicKey = keys.publicKey;
	    //cert.serialNumber = secureRandom.randomSerialNumber();
	    //cert.serialNumber = getSubSerialNr();
	    console.log("serialnr:   " + certSN);
	    cert.serialNumber = certSN;
	    cert.validity.notBefore = new Date();
	    var nfdate = new Date();
	    // add a day
	    nfdate.setDate(nfdate.getDate() + 1);
	    cert.validity.notAfter = nfdate;
	    // cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear());
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

	    cert.setSubject(attrs_subject);
	    // get sub_ca cert and sub_sub_ca cert in pem format
	    var subsubPem = fs.readFileSync(
		    './rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CACert.pem', 'utf8');
	    var subsubCA = forge.pki.certificateFromPem(subsubPem);
	    //start get authorityKeyIdentifier
	    var msg = forge.pem.decode(subsubPem)[0];
	    const object = forge.asn1.fromDer(msg.body);
	    var akeyHex = forge.asn1.prettyPrint(object);
	    console.log('akeyIdentifier1:  ' + akeyHex);
	    var ski = akeyHex.indexOf('subjectKeyIdentifier');
	    var val = akeyHex.substring(ski, (ski+180));
	    var valint1 = val.indexOf('Value: 0x');
	    var valint2 = val.indexOf(',');
	    val1 = val.substring((valint1+9), (valint1+9+14+valint2));
	    val1 = val1.replace(/..\B/g, '$&:');
	    console.log('akeyIdentifier2:  ' + val1 + '       ' + '        ' + valint1 + '     ' + (valint2));
	    
	    //end
	    cert.setIssuer(attrs_issuer);
		  cert.setExtensions([{
			    name: 'basicConstraints',
			    cA: true
			  }, {
			    name: 'keyUsage',
			    keyCertSign: true,
			    digitalSignature: true,
			    nonRepudiation: true,
			    keyEncipherment: true,
			    dataEncipherment: true
			  }, {
				  name: 'extKeyUsage',
				  serverAuth: true,
				  clientAuth: true,
				  codeSigning: true,
				  emailProtection: true,
				  timeStamping: true
				}, {
				    name: 'nsCertType',
				    client: true,
				    server: true,
				    email: true,
				    objsign: true,
				    sslCA: true,
				    emailCA: true,
				    objCA: true
				}, {
			    name: 'subjectAltName',
			    altNames: [{
			      type: 6, // URI
			      value: 'domain=http://'+newclient.commonName
			    }]}, {
				 name: 'subjectKeyIdentifier'
			    }, {
				name: 'authorityKeyIdentifier',
				value: 'keyid: '+val1
				//keyid: '20:D6:0E:C6:18:B1:76:C5:E2:65:8F:04:4F:41:78:5D:CA:6B:08:BE',
				//DirName: '/CN=Easy-RSA CA'
			    }, {
				name: 'authorityInfoAccess',
				value: 'https://www.prathamesh-phadnis.com',
//			        authorityInfoAccessIssuers: 'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt'
			    }, {
				name: 'cRLDistributionPoints',
				value: 'https://www.prathamesh-phadnis.com/domain_user'
			    }, {
				name: 'certificatePolicies',
				value: 'Policy: X509v3 Any Policy'+'\r\n'+
				       '  CPS: https://www.prathamesh-phadnis.com/repository/'
			    }
			    
			  ]);
	    // read ca root private key
	    let pkey = fs.readFileSync(
		    './rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CAprvKey.pem',
		    'utf8');
	    // let pkeyDer = forge.util.decode64(pkey); // since it's not base64
	    // encoded, i suppose don't need to decode
	    let privateKey = forge.pki.privateKeyFromPem(pkey);
	    console.log("loadCA_P12Cert002: ");
	    // self-sign certificate
	    cert.sign(privateKey);
	    console.log('Certificate Client_DOMAIN created.');
	    // get sub_ca cert and sub_sub_ca cert in pem format
	    // var subsubCA =
	    // fs.readFileSync('./rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CACert.pem',
	    // 'utf8');
	    var subCA = fs.readFileSync(
		    './rsa_sub_root/RSA_SUB_CA_DOMAINCert.pem', 'utf8');

	    // create PKCS12
	    console.log('\nCreating PKCS#12...');
	    var password = newclient.passphrase; //'pratham1234';
	    var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [
		    cert, subsubCA, subCA ], password,
		{
		    generateLocalKeyId : true,
		    friendlyName : newclient.organizationName //'pratham001'
		});
	    var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
	    //fs.writeFile('./rsa_domain/Client_DOMAINcertp12b64.p12',
	    fs.writeFile('./rsa_domain/'+newclient.clientId+'_'+newclient.p12FileName,
		    newPkcs12Der,
			{
			    encoding : 'binary'
			}, function(err, file) {
			if (err)
			    throw err;
			console.log('Saved  certCAp12b64.p12 file!');
		    });

	    // decrypt p12 using non-strict parsing mode (resolves some ASN.1
	    // parse errors)
	    var p12 = forge.pkcs12.pkcs12FromAsn1(newPkcs12Asn1, false, newclient.passphrase);
		    //'pratham1234');
	    var p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [ cert ], newclient.passphrase,
		    //'pratham1234',
			{
			    algorithm : '3des'
			});

	    // base64-encode p12
	    var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
	    var p12b64 = forge.util.encode64(p12Der);
	    console.log('\nBase64-encoded new PKCS#12:');
	    console.log(forge.util.encode64(newPkcs12Der));

	    // create CA store (w/own certificate in this example)
	    var caStore = forge.pki.createCaStore([ cert ]);

	    console.log('\nLoading new PKCS#12 to confirm...');
	    loadPkcs12(newPkcs12Der, password, caStore);
	} catch (ex)
	{
	    if (ex.stack)
		{
		    console.log(ex.stack);
		} else
		{
		    console.log('Error', ex);
		}
	}

    function loadPkcs12(pkcs12Der, password, caStore) {
	var pkcs12Asn1 = forge.asn1.fromDer(pkcs12Der);
	var pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, password);

	// load keypair and cert chain from safe content(s) and map to key ID
	var map =
	    {};
	for (var sci = 0; sci < pkcs12.safeContents.length; ++sci)
	    {
		var safeContents = pkcs12.safeContents[sci];
		console.log('safeContents ' + (sci + 1));

		for (var sbi = 0; sbi < safeContents.safeBags.length; ++sbi)
		    {
			var safeBag = safeContents.safeBags[sbi];
			console.log('safeBag.type: ' + safeBag.type);

			var localKeyId = null;
			if (safeBag.attributes.localKeyId)
			    {
				localKeyId = forge.util
					.bytesToHex(safeBag.attributes.localKeyId[0]);
				console.log('localKeyId: ' + localKeyId);
				if (!(localKeyId in map))
				    {
					map[localKeyId] =
					    {
						privateKey : null,
						certChain : []
					    };
				    }
			    } else
			    {
				// no local key ID, skip bag
				continue;
			    }

			// this bag has a private key
			if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag)
			    {
				console.log('found SUB_CA_DOMAIN private key');
				map[localKeyId].privateKey = safeBag.key;
			    } else if (safeBag.type === forge.pki.oids.certBag)
			    {
				// this bag has a certificate
				console.log('found Client_DOMAIN certificate');
				map[localKeyId].certChain.push(safeBag.cert);
			    }
		    }
	    }

	console.log('\nPKCS#12 Info:');

	for ( var localKeyId in map)
	    {
		var entry = map[localKeyId];
		console.log('\nLocal Key ID: ' + localKeyId);
		if (entry.privateKey)
		    {
			var privateKeyP12Pem = forge.pki
				.privateKeyToPem(entry.privateKey);
			var encryptedPrivateKeyP12Pem = forge.pki
				.encryptRsaPrivateKey(entry.privateKey,
					password);

			console.log('\nPrivate Key:');
			console.log(privateKeyP12Pem);
			fs
				.writeFile(
					'./rsa_domain/'+newclient.clientId+'_DOMAINprvKey.pem',
					privateKeyP12Pem,
					function(err, file) {
					    if (err)
						throw err;
					    console
						    .log('Saved  Client_DOMAINprvKey.pem file!');
					});
			console.log('Encrypted Private Key (password: "'
				+ password + '"):');
			console.log(encryptedPrivateKeyP12Pem);
		    } else
		    {
			console.log('');
		    }
		if (entry.certChain.length > 0)
		    {
			console.log('Certificate chain:');
			var certChain = entry.certChain;
			for (var i = 0; i < certChain.length; ++i)
			    {
				var certP12Pem = forge.pki
					.certificateToPem(certChain[i]);
				console.log(certP12Pem);
				fs
					.writeFile(
						'./rsa_domain/'+newclient.clientId+'_DOMAINCert.pem',
						certP12Pem,
						function(err, file) {
						    if (err)
							throw err;
						    console
							    .log('Saved  Client_DOMAINCert.pem file!');
						});
			    }

			var chainVerified = false;
			try
			    {
				chainVerified = forge.pki
					.verifyCertificateChain(caStore,
						certChain);
			    } catch (ex)
			    {
				chainVerified = ex;
			    }
			console.log('SUB CA Certificate chain verified: ',
				chainVerified);
		    }
	    }
    }

}
exports.createP12RSA_CLIENT_DOMAIN_TRUST_Cert = createP12RSA_CLIENT_DOMAIN_TRUST_Cert;
//createP12RSA_CLIENT_DOMAIN_TRUST_Cert("Ajeet Phadnis", '', '', '', '');
