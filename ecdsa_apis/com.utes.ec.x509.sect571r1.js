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
 */
var fs = require('fs');
const crypto = require('crypto');
const { Buffer } = require('buffer');
var forge = require('node-forge');
var pki = forge.pki;

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


var certSN;

function addDayToCurrentDate(days){
    let currentDate = new Date()
    return new Date(currentDate.setDate(currentDate.getDate() + days))
  }

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
    // hx = hx.replace(/..\B/g, '$&:');
    return hx;
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
  }

function createP12ECDSA_CLIENT_DOMAIN_TRUST_Cert(clientData, cacert, algType, req, res, next) {
    try	{
        // const args = process.argv.slice(3);
        // var type = args[0];
        // type='secp128r2';

      // read ca root private key
        var pkey = fs.readFileSync('./rsa_domain/logOn1_DOMAINprvKey.pem', 'utf8');
        console.log("privkey sub-sub-pem:  " + pkey);
        var snr = getSubSerialNr();
        var nbf = new Date();
        var nafdate = addDayToCurrentDate(1);
        console.log('dates: nbf: ' + nbf + '   nafdate:   ' + nafdate);
        console.log("clientData: " + JSON.stringify(clientData));
    	var data = JSON.stringify(clientData);
	JSON.parse(data, (key, value) => {
		  if (typeof value === 'string') {
		    // console.log("key: " + key);
		    if(key === 'clientId'){newclient.clientId = value;}
		    if(key === 'clientPw'){newclient.clientPw = value;}
		    if(key === 'commonName'){newclient.commonName = value;}
		    if(key === 'countryName'){newclient.countryName = value;}
		    if(key === 'ST'){newclient.ST = value;}
		    if(key === 'localityName'){newclient.localityName = value;}
		    if(key === 'organizationName'){newclient.organizationName = value;}
		    if(key === 'OU'){newclient.OU = value;}
		    if(key === 'keySize'){newclient.keySize = value;}
		    if(key === 'passphrase'){newclient.passphrase = value;}
		    if(key === 'p12FileName'){newclient.p12FileName = value;}
		  }
	});
	
        console.log("Algol Type:\t",newclient.keySize);
        
        // Generate Alice's keys...
     // Node.js program to demonstrate the
     // crypto.createECDH() method
     // Creating ECDH with curve name
     const curv = crypto.createECDH(newclient.keySize);
     curv.generateKeys();
     const pubkey = curv.getPublicKey();
     const prvkey = curv.getPrivateKey();
  // Print the PEM-encoded private key
     const privatePem = `-----BEGIN PRIVATE KEY-----
     ${Buffer.from(`308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420${curv.getPrivateKey('utf8')}a144034200${curv.getPublicKey('hex')}`, 'hex').toString('base64')}
-----END PRIVATE KEY-----`;
     console.log(privatePem);

     // Print the PEM-encoded public key
     const pubPem = `-----BEGIN PUBLIC KEY-----
	     ${Buffer.from(`3056301006072a8648ce3d020106052b8104000a034200${curv.getPublicKey('hex')}`, 'utf8').toString('base64')}
	     -----END PUBLIC KEY-----`;
     console.log(pubPem);

     // create a new certificate
        // var cert = pki.createCertificate();
        // var cert = forge.pki.createCertificate();
        var cert = new crypto.Certificate();
// const spkac = getSpkacSomehow();
// const publicKey = Certificate.exportPublicKey(spkac);
// console.log(publicKey);
        // console.log("Certificate: " + JSON.stringify(cert));
     // fill the required fields
        cert.publicKey = pubPem;
        cert.serialNumber = snr;
        // cert.validity.notBefore = nbf;
        cert.notBefore = nbf;
        cert.notAfter = nafdate;
        console.log("Certificate:   " + JSON.stringify(cert));
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

	    cert.subject = attrs_subject;
	    // get sub_ca cert and sub_sub_ca cert in pem format
	    console.log("CurrentPath:   " + __dirname);
	    var subsubPem = fs.readFileSync(
		    './rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CACert.pem', 'utf8');
	    var subsubCA = forge.pki.certificateFromPem(subsubPem);
	    // start get authorityKeyIdentifier
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
	    
	    // end
	    cert.issuer = attrs_issuer;
	    /*
	     * cert.setExtensions([{ name: 'basicConstraints', CA: true }, {
	     * name: 'keyUsage', keyCertSign: true, digitalSignature: true,
	     * nonRepudiation: true, keyEncipherment: true, dataEncipherment:
	     * true }, { name: 'extKeyUsage', serverAuth: true, clientAuth:
	     * true, codeSigning: true, emailProtection: true, timeStamping:
	     * true }, { name: 'nsCertType', client: true, server: true, email:
	     * true, objsign: true, sslCA: true, emailCA: true, objCA: true }, {
	     * name: 'subjectAltName', altNames: [{ type: 6, // URI value:
	     * 'domain=http://'+newclient.commonName }]}, { name:
	     * 'subjectKeyIdentifier' }, { name: 'authorityKeyIdentifier',
	     * value: 'keyid: '+val1 //keyid:
	     * '20:D6:0E:C6:18:B1:76:C5:E2:65:8F:04:4F:41:78:5D:CA:6B:08:BE',
	     * //DirName: '/CN=Easy-RSA CA' }, { name: 'authorityInfoAccess',
	     * value: 'https://www.prathamesh-phadnis.com', //
	     * authorityInfoAccessIssuers:
	     * 'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt' }, {
	     * name: 'cRLDistributionPoints', value:
	     * 'https://www.prathamesh-phadnis.com/domain_user' }, { name:
	     * 'certificatePolicies', value: 'Policy: X509v3 Any Policy'+'\r\n'+ '
	     * CPS: https://www.prathamesh-phadnis.com/repository/' }
	     * 
	     * ]);
	     */
	    // read ca root private key
	    pkey = fs.readFileSync(
		    './rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CAprvKey.pem',
		    'binary');
	    console.log("loadCA_P12Cert001: " + pkey);
	    // let pkeyDer = forge.util.decode64(pkey); // since it's not base64
	    // encoded, i suppose don't need to decode
	    // let privateKey = forge.pki.privateKeyFromPem(pkey);
	    // console.log("loadCA_P12Cert002: " + JSON.stringify(privateKey));
	    // self-sign certificate
	    var sign = crypto.createSign('RSA-SHA256');
	    var key = pkey.toString('ascii');
	    sign.update(JSON.stringify(cert));  // data from your file would go
						// here
	    var sig = sign.sign(key, 'hex');
	    console.log('Certificate Client_DOMAIN created:    '  + JSON.stringify(sign));
	    // get sub_ca cert and sub_sub_ca cert in pem format
	     var subsubCA =
	     fs.readFileSync('./rsa_sub_sub_root/RSA_DOMAIN_SUB_SUB_CACert.pem',
	     'utf8');
	    var subCA = fs.readFileSync('./rsa_sub_root/RSA_SUB_CA_DOMAINCert.pem', 'utf8');

	    // create PKCS12
	    var acert = `-----BEGIN CERTIFICATE-----
MIIEPjCCAyagAwIBAgIGApAiBgknMA0GCSqGSIb3DQEBBQUAMIG3MSwwKgYDVQQD
EyNwcmF0aGFtZXNoLXBoYWRuaXMuY29tL3N1YmNhLWRvbWFpbjELMAkGA1UEBhMC
Tk8xETAPBgNVBAgTCEFrZXJodXNhMQ0wCwYDVQQHEwRPc2xvMS8wLQYDVQQKEyZQ
cmF0aGFtUGhhZG5pc19TVUJfQ0FfVFJVU1RfRE9NQUlOIEluYzEnMCUGA1UECxMe
U1VCX0NBX1RSVVNUX0RPTUFJTiBDcnlwdG9BcHBzMB4XDTIxMDkyNzE1MjYzNloX
DTIxMDkyODE1MjYzNlowdzETMBEGA1UEAxMKbG9nT24xLmNvbTEMMAoGA1UEBhMD
VVNBMRIwEAYDVQQIEwlsb2dPbjFJbmMxEDAOBgNVBAcTB0x1c2lhbmExEjAQBgNV
BAoTCWxvZ09uMUluYzEYMBYGA1UECxMPbG9nT24xX3NlY3VyaXR5MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnnQWupIkrGJ95bkJeBBmUz64jBNoG6V
c7mQA9kxFkfkvva0xAJdubaCyt7QMRmvYgzXaocAdH7Ga33adUNj4WVVEwJDEzir
TQbM8hdqAnFMuVOj4CI4eqXFbyeS+OubNSBWLiX3XFupU3/kgjopE+M0QJcEIerl
HmmeojMDsaSqIvgCEpCcLKmq8N8C47BAaaIm1IKbWPOZTS0P3tpXwYNlk43kuezx
qA/XHy8t/JTzB/NuDIY0bpd4/AHlSxv1W+881R9kpPOz6XzLBoLnFD9lZD5jWDq4
qJzYRrkcxy9jpK2FPXvwq6w8vkzEnB75sZ1Isi9Ag2vkj6fDvTTeaQIDAQABo4GO
MIGLMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgL0MB0GA1UdDgQWBBRl9kQuvktF
hpzHKgcss51pgiE62zAJBgNVHSMEAjAAMEQGA1UdEQQ9MDuGOWh0dHBzOi8vd3d3
LnByYXRoYW1lc2gtcGhhZG5pcy5jb20vc3ViX3N1YmNhLWRvbWFpbi9hZG1pbjAN
BgkqhkiG9w0BAQUFAAOCAQEAa79HvvBFnY4Yac5MUZGbbOoTyeXhg+KSsA1YeOp5
f7UNWHWTipKAbyamGrp/zXk7lhFW5nGk7S4Uo70hne5D+aQHzJGluPCaIt2TBz0d
w9BJW/vSW5FMusQPqKyx9nlDrwmgTag0Nl31i3ZcjHxGPePOKay5X9UlEOzDZ6RV
PmCC3MNlNWwv5NXLf61IETtlGcvg35BoKDZ8WoKN4Gz82rn33NFr9Y17R6+fqG94
6UEJ6mh9GoLeqcVzAXtzKAcmL9mpkgVeJs89vdIFi8n3KvVbure0UPV1ztG2QU+6
cSXYIE6FTyACRS9TgvGtq/tbFiOCBOje9ttxyf7ghsu1gQ==
-----END CERTIFICATE-----
`;
	    console.log('\nCreating PKCS#12...');
	    var certStr = JSON.stringify(cert);
	    var certPem = `-----BEGIN CERTIFICATE-----\r\n`+certStr+`\r\n-----END CERTIFICATE-----\r\n`;
	    var password = newclient.passphrase; // 'pratham1234';
	    console.log('\nPassphrase:   ' + password);
	    console.log('\nCertificate:   ' + certPem);
	    var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(pkey, [
		acert, subsubCA, subCA ], password,
		{
		    generateLocalKeyId : true,
		    friendlyName : newclient.organizationName // 'pratham001'
		});
	    var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
	    // fs.writeFile('./rsa_domain/Client_DOMAINcertp12b64.p12',
	    fs.writeFile('./ec_domain/'+newclient.clientId+'_'+newclient.p12FileName,
		    newPkcs12Der,
			{
			    encoding : 'binary'
			}, function(err, file) {
			if (err) {
			    throw err;
			}
			console.log('Saved  certCAp12b64.p12 file!');
		    });

	    // decrypt p12 using non-strict parsing mode (resolves some ASN.1
	    // parse errors)
	    var p12 = forge.pkcs12.pkcs12FromAsn1(newPkcs12Asn1, false, newclient.passphrase);
		    // 'pratham1234');
	    var p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [ cert ], newclient.passphrase,
		    // 'pratham1234',
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

    } catch (ex) {
	if (ex.stack) {
	    console.log(ex.stack);
	} else	{
	    console.log('Error', ex);
	}
    }
}
        
exports.createP12ECDSA_CLIENT_DOMAIN_TRUST_Cert = createP12ECDSA_CLIENT_DOMAIN_TRUST_Cert;

createP12ECDSA_CLIENT_DOMAIN_TRUST_Cert(newclient, '', 'secp521r1', '', '', '');