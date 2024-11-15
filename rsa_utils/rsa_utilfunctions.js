/**
 * http://usejsdoc.org/
 */
var forge = require('node-forge');
var fs = require('fs');


        var getCA_P12_PrivateKey = function ( filePath, pass ) {
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
        		return pemPrivate;
        }
        	
        var getCA_P12_Cert = function (filePath, pass) {
            var keyFile = fs.readFileSync(filePath, 'binary');
        	    var p12Asn1 = forge.asn1.fromDer(keyFile);
        	    var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);
        	    var bags = p12.getBags({bagType: forge.pki.oids.certBag});
        	    var bag = bags[forge.pki.oids.certBag][0];
        	    // convert to ASN.1, then DER, then PEM-encode
        	    var msg = {
        	      type: 'CERTIFICATE',
        	      body: forge.asn1.toDer(bag.asn1).getBytes()
        	    };
        	    var pem_cert = forge.pem.encode(msg);
        	    console.log(pem_cert);
        	    return pem_cert
        	}


	var getSUB_CA_P12_PrivateKey = function ( filePath, pass ) {
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
			return pemPrivate;
	}
		
	var getSUB_CA_P12_Cert = function (filePath, pass) {
	    var keyFile = fs.readFileSync(filePath, 'binary');
		    var p12Asn1 = forge.asn1.fromDer(keyFile);
		    var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);
		    var bags = p12.getBags({bagType: forge.pki.oids.certBag});
		    var bag = bags[forge.pki.oids.certBag][0];
		    // convert to ASN.1, then DER, then PEM-encode
		    var msg = {
		      type: 'CERTIFICATE',
		      body: forge.asn1.toDer(bag.asn1).getBytes()
		    };
		    var pem_cert = forge.pem.encode(msg);
		    console.log(pem_cert);
		    return pem_cert
		}

	var getSUB_SUB_CA_P12_PrivateKey = function ( filePath, pass ) {
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
			return pemPrivate;
	}
		
	var getSUB_SUB_CA_P12_Cert = function (filePath, pass) {
	    var keyFile = fs.readFileSync(filePath, 'binary');
		    var p12Asn1 = forge.asn1.fromDer(keyFile);
		    var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);
		    var bags = p12.getBags({bagType: forge.pki.oids.certBag});
		    var bag = bags[forge.pki.oids.certBag][0];
		    // convert to ASN.1, then DER, then PEM-encode
		    var msg = {
		      type: 'CERTIFICATE',
		      body: forge.asn1.toDer(bag.asn1).getBytes()
		    };
		    var pem_cert = forge.pem.encode(msg);
		    console.log(pem_cert);
		    return pem_cert
	}
	
	// a hexString is considered negative if it's most significant bit is 1
	// because serial numbers use ones' complement notation
	// this RFC in section 4.1.2.2 requires serial numbers to be positive
	// http://www.ietf.org/rfc/rfc5280.txt
	function toPositiveHex(hexString){
	  var mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
	  if (mostSiginficativeHexAsInt < 8){
	      console.log("Random:  " + hexString);
	    return hexString;
	  }

	  mostSiginficativeHexAsInt -= 8;
	  return mostSiginficativeHexAsInt.toString() + hexString.substring(1);
	}

	function randomSerialNumber () {
	    return toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)))
	}
	
exports.randomSerialNumber = randomSerialNumber;
randomSerialNumber();
