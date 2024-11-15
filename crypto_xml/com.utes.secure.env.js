/**
 * http://usejsdoc.org/
 */
var select = require('xml-crypto').xpath
  ,	xpath = require('xpath')
  , dom = require('xmldom').DOMParser
  , SignedXml = require('xml-crypto').SignedXml
  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
  , fs = require('fs');

var jose = require('node-jose');
var forge = require('node-forge');
var privateKeyP12Pem;
var certP12Pem;
var status = false;
var keyinfo;
var certSN;
var kinf;
var endStr = `
	</ApplicationRequest>`;

var newenvVals = {
	CustomerId: String,
	Timestamp: String,
	TargetId: String,
	Content: String,
	keyInfo: String
};

var certSN;


const readFile = (filePath, encoding) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, encoding, (err, data) => {
            if (err) {
                return reject(err);
            }
            resolve(data);
            console.log(data.toString());
            return data.toString();
        });
    });
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



const readP12PrvKey = async (clntData, clntId, filePath, pass, fileEnv) => {
	try {
		console.log("readP12PrvKey:clntData:  " + JSON.stringify(clntData));
		console.log("readP12PrvKey:clntId:  " + clntId);
		console.log("readP12PrvKey:filePath:  " + filePath);
		console.log("readP12PrvKey:pass:  " + pass);
		console.log("readP12PrvKey:fileEnv:  " + fileEnv);
		// read payload file
		var payload = await readFile('./rsa_domain/Integration_grp_Pain001.xml');
		var b64Str = Buffer.from(payload).toString('base64');
		//read client p12 file
		var keyFile = await fs.readFileSync(filePath, 'binary');
		var p12Asn1 = await forge.asn1.fromDer(keyFile, false);
		var p12 = await forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, pass);
		// get key bags
		// load keypair and cert chain from safe content(s) and map to key ID
		  var map = {};
		  for(var sci = 0; sci < p12.safeContents.length; ++sci) {
		    var safeContents = p12.safeContents[sci];
		    console.log('safeContents ' + (sci + 1));
	
		    for(var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
		      var safeBag = safeContents.safeBags[sbi];
		      console.log('safeBag.type: ' + safeBag.type);
	
		      var localKeyId = null;
		      if(safeBag.attributes.localKeyId) {
		        localKeyId = await forge.util.bytesToHex(
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
		        console.log('found private key');
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
		      privateKeyP12Pem = await forge.pki.privateKeyToPem(entry.privateKey);
		      var encryptedPrivateKeyP12Pem = await forge.pki.encryptRsaPrivateKey(
		        entry.privateKey, pass);
	
		      console.log('\nPrivate Key:');
		      console.log(privateKeyP12Pem);	      
		      fs.writeFile('./rsa_domain/'+clntId+'_DomainprvKey.pem', privateKeyP12Pem, function (err, file) {
					if (err) throw err;
					console.log('Saved  privKey.pem file!');
				});
		      console.log('Encrypted Private Key (password: "' + pass + '"):');
	//	      console.log(encryptedPrivateKeyP12Pem);
		      if(entry.certChain.length > 0) {
			      console.log('Certificate chain:');
			      var certChain = entry.certChain;
			      for(var i = 0; i < certChain.length; ++i) {
			        certP12Pem = await forge.pki.certificateToPem(certChain[i]);
			        console.log("x509Cert:  " + certP12Pem);
			        var remHeaderCert = certP12Pem.replace('-----BEGIN CERTIFICATE-----', '');
			        remHeaderCert = remHeaderCert.replace('-----END CERTIFICATE-----', '');
			        remHeaderCert = remHeaderCert.replace(/\r?\n|\r/g, "");
			        const cert = await forge.pki.certificateFromPem(certP12Pem);
			        const subject = cert.subject.attributes
			          .map(attr => [attr.shortName, attr.value].join('='))
			          .join(', ');	
			        console.log(subject); // "C=US, ST=California, ..."
			        newenvVals.CustomerId = clntData.CustomerId;
			        newenvVals.TargetId = clntData.TargetId;
			        //var b64Str = Buffer.from("This is test string").toString('base64');
			        var b64Str = Buffer.from(clntData.Content).toString('base64');
			        newenvVals.Content = b64Str;
			        newenvVals.keyInfo = keyinfo;
			     // version
			        console.log(cert.version);
			        // serial number
			        certSN = getSubSerialNr();
			        console.log(certSN);
			        // validity
			        console.log(cert.validity['notBefore']);
			        // issuer
			        // all issuer attributes			        
			        var issuAttrs = JSON.stringify(cert.issuer.attributes);
			        var issuVals = JSON.parse(issuAttrs);
			        console.log('IssuerAttrs:   ' + JSON.stringify(issuVals['CN']));
			        // get, for example, common name via its short name "CN"
			        console.log(cert.issuer.getField('CN').value);
			        console.log(cert.issuer.getField('C'));
			        // subject
			        console.log(cert.subject);
			        // all subject attributes
			        console.log(cert.subject.attributes);
			        // get, for example, common name via its short name "CN"
			        console.log(cert.subject.getField('CN'));
			        cnName = cert.subject.getField('CN').toString();
			        var issuerStr = 'SERIALNUMBER='+certSN+','+'CN='+cert.issuer.getField('CN').value+','+'O='+cert.issuer.getField('O').value+','+'C='+cert.issuer.getField('C').value;
			        keyinfo = 
			        	`<X509IssuerSerial><X509IssuerName>`+issuerStr+`</X509IssuerName><X509SerialNumber>`+certSN+`</X509SerialNumber></X509IssuerSerial><X509Certificate>`+remHeaderCert+`</X509Certificate>`;
			        await fs.writeFile('./rsa_domain/'+clntId+'_DomainCert.pem', certP12Pem, function (err, file) {
						if (err) throw err;
						console.log('Saved  Integration_Cert.pem file!');
					});
			      }
		      }
		    }
		  }
		}  catch (e) {
		    console.log('e', e);
		    status = false;
		}
	  if (filePath === undefined) {
	    console.log('filePath undefined');
	    status = false;
	  } else {
	    console.log('filePath', filePath);
	    status = true;
	  }
	  if (status) {
		  try {
			  var tempEnv = await fs.readFileSync(fileEnv, 'binary');
			  console.log('tempEnv:  ' + tempEnv);
			  var xmlStr = await envModifyXml(tempEnv, newenvVals);
			  console.log("xml with sig:   " + xmlStr);
			// sign an xml document
			var signedXml1 = await signXml(xmlStr, 
			  "//*[local-name(.)='Content']", 
			  "./rsa_domain/"+clntId+"_DOMAINprvKey.pem", 
			  "./crypto_xml/ApplicationRequest.xml");	
			var signedXml = fs.readFileSync("./crypto_xml/ApplicationRequest.xml").toString();
			console.log("xml signed succesfully: 00001   " + signedXml);
			//validate an xml document
			//var ret = await validateXml(signedXml, certP12Pem);
			if (await validateXml(signedXml, "./rsa_domain/"+clntId+"_DomainCert.pem") ) {
			  console.log("signature is valid:   " );
			} else {
			  console.log("signature not valid:   " );
			  return signedXml;
			}
		  } catch (e) {
			    console.log('e', e);
			    status = false;
			}
	  }
	  
}

/**/
function getKeyInfo() {
  this.getKeyInfo = function(key, prefix) {
    prefix = prefix || '';
    prefix = prefix ? prefix + ':' : prefix;
    kinf = "<" + prefix + "X509Data>"+keyinfo+"</" + prefix + "X509Data>";
	console.log("getKeyInfo:   " + kinf);
    return kinf;
  }
  this.getKey = function(keyInfo) {
    //you can use the keyInfo parameter to extract the key in any way you want      
    return fs.readFileSync("./rsa_domain/privKey.pem");
  }
}

async function signXml(xml, xpath, key, dest) {
  var sig = new SignedXml();  
  console.log("signXml001:   " );
  sig.keyInfoProvider = await new getKeyInfo();
  //sig.keyInfoProvider = new FileKeyInfo('./rsa_domain/Integration_Cert.pem'); 
  sig.signingKey = await readFile(key);
  console.log("signXml002:   ");
  await sig.addReference("//*[local-name(.)='Content']");
  console.log("signXml003:   ");
  await sig.computeSignature(xml);  console.log("signXml004:   ");
  var xmlStr = sig.getSignedXml();
  console.log("signXml005:   " + xmlStr);
  await fs.writeFileSync(dest, xmlStr);
  return xmlStr;
}

async function validateXml(xml1, key) {
	try {
		xml = fs.readFileSync('./crypto_xml/ApplicationRequest.xml').toString();
		console.log('validateXml:signedXml:  ' + xml);
	  var doc = await new dom().parseFromString(xml,"text/xml");    
	  var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
	  var sig = new SignedXml();
	  console.log("validate result001:  ");
	  //sig.addReference("//*[local-name(.)='Signature']", ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'], 'http://www.w3.org/2001/04/xmlenc#sha256');
	  sig.keyInfoProvider = new FileKeyInfo(key);
	  console.log("validate result002:  ");
	  //await sig.loadSignature(signature.toString());
	  console.log("validate result003:  ");
	  sig.loadSignature(signature);
	  console.log("validate result004:  ");
	  var res = sig.checkSignature(xml);
	  console.log("validate result005:  " + res);
	  if (!res) console.log(sig.validationErrors);
	  console.log("validate result006:  " + res);
	  return res;
	} catch (e) {
	    //console.log('e', e);
	    status = false;
	}  
}

// how the node values are used:
// nodeValue on an element will return null. However on a text node it will return the value. 
// Since text is treated as a node you need to select another childnode. 
// textContent gives you all the text inside the element.
// Different node-types. Text inside a node is treated as a text-node. 
// That's why nodeValue on the element returned null. Table from MDN
async function envModifyXml(xml, envData) {
	try {
		//console.log( "xml: " + xml );
		var parser = new dom();
		var document = parser.parseFromString( xml , "text/xml");
		// this won't work, but no error
		//document.getElementsByTagName("CustomerId")[0].childNodes[0].data = "98765";
		document.getElementsByTagName('CustomerId')[0].textContent = envData.CustomerId;
		document.getElementsByTagName( "TargetId" )[0].textContent = envData.TargetId;
		txt = document.getElementsByTagName("SoftwareId")[0].childNodes[0].nodeValue;
		document.getElementsByTagName( "Content" )[0].textContent = envData.Content;
		//document.getElementsByTagName( "KeyInfo" )[0].textContent = envData.keyInfo;
		console.log( "SoftwareId: " + txt);
		var XMLSerializer = require( 'xmldom' ).XMLSerializer;
		var serializer = new XMLSerializer();
		var xmlstring = serializer.serializeToString( document );
		console.log( "xmlstring: " + xmlstring );
		return xmlstring;
	} catch (e) {
	    console.log('e', e);
	    status = false;
	}
}
exports.readP12PrvKey = readP12PrvKey;
exports.newenvVals = newenvVals;

//readP12PrvKey('', 'OktaUser', './rsa_domain/Integration_grp_integration_cert.p12', 'Integration_grp', './crypto_xml/nordea_EnvelopeTemplate.xml');

