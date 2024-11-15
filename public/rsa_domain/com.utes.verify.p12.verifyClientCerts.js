/*



*/

var forge = require('node-forge');
var fs = require('fs');




function compareDates(date1, date2, date3) {
    var g1 = date1;
    var g2 = date2;
    var g3 = date3;
    
    if (g1.getTime() < g2.getTime()) {
        console.log("date/time present is lesser than not-before");
        console.log("Certificate date validity not started");
        return 'NOT_BEFORE';
    } else if ((g1.getTime() > g2.getTime()) && (g1.getTime() < g3.getTime())) {
	console.log("date/time present is greater than not-before");
	console.log("date/time present is lesser than not-after");
	console.log("Certificate date validity passed");
	return 'OK';
    } else if ((g1.getTime() > g3.getTime())) {
	console.log("date/time present is greater than not-after");
	console.log("Certificate date validity expired");
	return 'EXPIRED';
    } else {
	console.log("both are equal");
	return 'OK_EQL';
    }
}

function getP12PrivateKey ( user, filePath, pass ) {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: ");
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: ");
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPrivate = forge.pki.privateKeyToPem(key);
		console.log(pemPrivate);
		// DUMP_PRIVATE_KEY = pemPrivate;
		return pemPrivate;
}


function getP12Certs(req, res, user, filePath, pass) {
    var keyFile = fs.readFileSync(filePath, 'binary');
    var p12Asn1 = forge.asn1.fromDer(keyFile);
    var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);
    var bags = p12.getBags({bagType: forge.pki.oids.certBag});
    var bag = bags[forge.pki.oids.certBag][0];
    var certStat;
    // convert to ASN.1, then DER, then PEM-encode
    // generate pem from cert
    var certificate = forge.pki.certificateToPem(bag.cert);
	    // var pem_cert = forge.pem.encode(msg);
	    const cert = forge.pki.certificateFromPem(certificate);
	    const caStore = forge.pki.createCaStore([ cert ]);
	    var verify = forge.pki.verifyCertificateChain(caStore, [ cert ], null);
	    if (verify) {
		console.log("CA-Cert verify:  successful  " + verify);
	    } else {
		console.log("CA-Cert verify:  failed  " + verify);
	    }
	    
	    var stat = compareDates(new Date(), cert.validity.notBefore, cert.validity.notAfter);
	    if (stat === 'OK' && verify) {
		certStat = 'GOOD';
	    } else {
		certStat = 'NOT_GOOD';
	    }
	    // return certificate;
	    const prvKey = getP12PrivateKey(user, filePath, pass);
	    hashForge = forge.md.sha1.create();
	    const keyHash = hashForge.update((cert.issuer.getField('CN').value).toString("binary"));
	    const keySh = hashForge.digest().toHex();
	    const orgHash = hashForge.update((cert.issuer.getField('O').value).toString("binary"));
	    const orgSh = hashForge.digest().toHex();
	    const data = {
		    OCSPResponsestatus: cert.subject.getField('CN').value,
		    ResponseType: 'Basic OCSP Response',
		    Version: 1,
		    ResponderID: cert.issuer.getField('CN').value,
		    ProducedAt: new Date(),		    
		    ResponseList_HashAlgorithm: 'SHA1',
		    ResponseList_IssuerNameHash: orgSh,
		    ResponseList_IssuerKeyHash: keySh,
		    ResponseList_CertStatus: certStat,
		    ResponseList_RevocationTime: '',
		    ResponseList_ThisUpdate: new Date(),
		    ResponseList_NextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
		    countryName: cert.issuer.getField('C').value,
		    organizationName: cert.issuer.getField('O').value,
		    serialNumber: cert.serialNumber,
		    notBefore: cert.validity.notBefore,
		    notAfter: cert.validity.notAfter,
		  };
		  // return data;
// const subject = cert.subject.attributes
// .map(attr => [attr.shortName, attr.value].join('='))
// .join(', ');	    
	    var pretty = JSON.stringify(data, undefined, 4);
	    console.log("cert data:  " + pretty);
	    return pretty;
}




exports.getP12Certs = getP12Certs;
exports.getP12PrivateKey = getP12PrivateKey;

// getP12Certs('', '', 'logOn1', './rsa_domain/logOn1_logOn1.p12', 'logOn1');
// getP12PrivateKey('kunalpandya', './user_certs/kunalpandya_certp12b64.p12', 'kunalpandya');