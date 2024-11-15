// http://ospkibook.sourceforge.net/docs/OSPKI-2.4.7/OSPKI-html/sample-ca-cert-txt.htm
// https://github.com/ThauEx/ffrk-proxy/blob/master/tests/createRootCa.js
// https://github.com/ThauEx/ffrk-proxy/blob/master/lib/cert.js
// http://www.steves-internet-guide.com/ssl-certificates-explained/
// https://medium.com/two-cents/certificate-chain-example-e37d68c3a3f0
/*
Third one is USERTrustRSAAddTrustCA.crt:
Issuer: C=SE, O=AddTrust AB, OU=AddTrust External TTP Network, CN=AddTrust External CA Root
Subject: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust RSA Certification Authority
Last one is AddTrustExternalCARoot.crt. Note: Issuer = Subject, means it is root CA. There is no need to 
add root CA certificate to the chain. It doesn’t brake it but it increases amount of handshakes and 
amount of transmitted data.

 */
var forge = require('node-forge');
var fs = require('fs');
var secureRandom = require('secure-random');

function createP12RSA_CAROOTCert(uid, text, req, res, next) {
	try {
		  // generate a keypair
		  console.log('Generating 4096-bit CA - key-pair...');
		  var keys = forge.pki.rsa.generateKeyPair(4096);
		  console.log('CA Key-pair created.');
		  // create random serial no
		  var bytes = secureRandom(10, {type: 'Buffer'}) //return a Buffer of 10 bytes
		  console.log(bytes.length) //10

		  // create a certificate
		  console.log('Creating self-signed CA certificate...');
		  var cert = forge.pki.createCertificate();
		  cert.publicKey = keys.publicKey;
		  cert.serialNumber = '01';
		  cert.validity.notBefore = new Date();
		  cert.validity.notAfter = new Date();
		  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 20);
		  var attrs = [{
		    name: 'commonName',
		    value: 'prathamesh-phadnis.com'
		  }, {
		    name: 'countryName',
		    value: 'NO'
		  }, {
		    shortName: 'ST',
		    value: 'Akerhusa'
		  }, {
		    name: 'localityName',
		    value: 'Oslo'
		  }, {
		    name: 'organizationName',
		    value: 'PrathamPhadnisCA Inc'
		  }, {
		    shortName: 'OU',
		    value: 'CA CryptoApps'
		  }];
		  cert.setSubject(attrs);
		  cert.setIssuer(attrs);
		  cert.setExtensions([{
		    name: 'basicConstraints',
		    cA: true
//		  }, {
//		    name: 'keyUsage',
//		    keyCertSign: true,
//		    digitalSignature: true,
//		    nonRepudiation: true,
//		    keyEncipherment: true,
//		    dataEncipherment: true
		  }, {
			    name: 'subjectKeyIdentifier'
		  }, {
		      name: 'authorityKeyIdentifier'
		  }, {
		    name: 'subjectAltName',
		    altNames: [{
		      type: 6, // URI
		      value: 'https://www.prathamesh-phadnis.com/admin'
		    }]
		  }]);

		  // self-sign certificate
		  cert.sign(keys.privateKey);
		  console.log('Certificate CA ROOT created.');

		  // create PKCS12
		  console.log('\nCreating PKCS#12...');
		  var password = 'pratham1234';
		  var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
		    keys.privateKey, [cert], password,
		    {generateLocalKeyId: true, friendlyName: 'pratham001'});
		  var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
		  fs.writeFile('./rsa_root/RSA_CAROOTcertp12b64.p12', newPkcs12Der, {encoding: 'binary'} , function (err, file) {
				if (err) throw err;
				console.log('Saved  certCAp12b64.p12 file!');
			});

		  // decrypt p12 using non-strict parsing mode (resolves some ASN.1 parse errors)
		  var p12 = forge.pkcs12.pkcs12FromAsn1(newPkcs12Asn1, false, 'pratham1234');
		  var p12Asn1 = forge.pkcs12.toPkcs12Asn1(
				  keys.privateKey, [cert], 'pratham1234',
				  {algorithm: '3des'});
				 
				// base64-encode p12
		  var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
		  var p12b64 = forge.util.encode64(p12Der);
		  console.log('\nBase64-encoded new PKCS#12:');
		  console.log(forge.util.encode64(newPkcs12Der));

		  // create CA store (w/own certificate in this example)
		  var caStore = forge.pki.createCaStore([cert]);

		  console.log('\nLoading new PKCS#12 to confirm...');
		  loadPkcs12(newPkcs12Der, password, caStore);
		} catch(ex) {
		  if(ex.stack) {
		    console.log(ex.stack);
		  } else {
		    console.log('Error', ex);
		  }
		}

		function loadPkcs12(pkcs12Der, password, caStore) {
		  var pkcs12Asn1 = forge.asn1.fromDer(pkcs12Der);
		  var pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, password);
		  
		  // load keypair and cert chain from safe content(s) and map to key ID
		  var map = {};
		  for(var sci = 0; sci < pkcs12.safeContents.length; ++sci) {
		    var safeContents = pkcs12.safeContents[sci];
		    console.log('safeContents ' + (sci + 1));

		    for(var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
		      var safeBag = safeContents.safeBags[sbi];
		      console.log('safeBag.type: ' + safeBag.type);

		      var localKeyId = null;
		      if(safeBag.attributes.localKeyId) {
		        localKeyId = forge.util.bytesToHex(
		          safeBag.attributes.localKeyId[0]);
		        console.log('localKeyId: ' + localKeyId);
		        if(!(localKeyId in map)) {
		          map[localKeyId] = {
		            privateKey: null,
		            certChain: []
		          };
		        }
		      } else {
		        // no local key ID, skip bag
		        continue;
		      }

		      // this bag has a private key
		      if(safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
		        console.log('found CAROOT private key');
		        map[localKeyId].privateKey = safeBag.key;
		      } else if(safeBag.type === forge.pki.oids.certBag) {
		        // this bag has a certificate
		        console.log('found certificate');
		        map[localKeyId].certChain.push(safeBag.cert);
		      }
		    }
		  }

		  console.log('\nPKCS#12 Info:');

		  for(var localKeyId in map) {
		    var entry = map[localKeyId];
		    console.log('\nLocal Key ID: ' + localKeyId);
		    if(entry.privateKey) {
		      var privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
		      var encryptedPrivateKeyP12Pem = forge.pki.encryptRsaPrivateKey(
		        entry.privateKey, password);

		      console.log('\nPrivate Key:');
		      console.log(privateKeyP12Pem);
		      fs.writeFile('./rsa_root/RSA_CAROOTprvKey.pem', privateKeyP12Pem, function (err, file) {
					if (err) throw err;
					console.log('Saved  caPrvKey.pem file!');
				});
		      console.log('Encrypted Private Key (password: "' + password + '"):');
		      console.log(encryptedPrivateKeyP12Pem);
		    } else {
		      console.log('');
		    }
		    if(entry.certChain.length > 0) {
		      console.log('Certificate chain:');
		      var certChain = entry.certChain;
		      for(var i = 0; i < certChain.length; ++i) {
		        var certP12Pem = forge.pki.certificateToPem(certChain[i]);
		        console.log(certP12Pem);
		        fs.writeFile('./rsa_root/RSA_CAROOTCert.pem', certP12Pem, function (err, file) {
					if (err) throw err;
					console.log('Saved  CACert.pem file!');
				});
		      }

		      var chainVerified = false;
		      try {
		        chainVerified = forge.pki.verifyCertificateChain(caStore, certChain);
		      } catch(ex) {
		        chainVerified = ex;
		      }
		      console.log('CA ROOT Certificate chain verified: ', chainVerified);
		    }
		  }
		}

}
exports.createP12RSA_CAROOTCert = createP12RSA_CAROOTCert;
createP12RSA_CAROOTCert("Ajeet Phadnis", '', '', '', '');