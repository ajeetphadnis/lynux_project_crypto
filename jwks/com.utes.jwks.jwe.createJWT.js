const {JWE} = require("node-jose");
const {JWK} = require("node-jose");
const {JWS} = require("node-jose");
const {util} = require("node-jose");
const fs = require('fs');
const forge = require("node-forge");
//const jwt_decode = require("jwt-decode");
var contentAlg = "A256CBC-HS512";

const payload = {
        'iss': 'idp.utes.com', 'sub': '', 'aud': 'https://utes.com/saml', 'nbf': '', 'iat': '', 'exp': '' };

async function getX509Details (uid, x5cStr, pass) {
	//var pem = await readFile(filePath);
	var pem = x5c_to_cert (x5cStr);
	console.log('getX509Details:001   ' + pem);
	const cert = forge.pki.certificateFromPem(pem);
	var caStore = forge.pki.createCaStore(cert);
	var cn = cert.issuer.getField('CN').value;
	var issuer_ou = cert.issuer.getField('OU').value;
	var issuer_o = cert.issuer.getField('O').value;
	var naf = cert.validity.notAfter;
	var date = new Date(naf);
	var seconds = date.getTime() / 1000; // 1440516958
	payload.iat = seconds+36000;
	payload.exp = seconds+36000;
	console.log("getX509Details002:  " + naf + "       " + seconds); 
	var nbfv = cert.validity.notBefore;
	console.log(nbfv);
	var date = new Date(nbfv);
	seconds = date.getTime() / 1000; // 1440516958
	payload.nbf = seconds+36000;
	console.log("getX509Details003:  " + nbfv + "       " + seconds);
	console.log(cert.serialNumber);
	payload.sub = cert.subject.getField('CN').value;
	var co = cert.subject.getField('CN').value;
	console.log("getX509Details004:  " + cn);
	console.log("getX509Details005:  " + issuer_ou);
	console.log("getX509Details006:  " + issuer_o);
	console.log("getX509Details007:  " + JSON.stringify(payload));
	return JSON.stringify(payload);
}

const getCA_P12_PrivKey = async ( uid, filePath, pass ) => {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: " + filePath +  '  ' + pass);
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: ");
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPrivate = forge.pki.privateKeyToPem(key);
		console.log(pemPrivate);
		//DUMP_PRIVATE_KEY = pemPrivate;
		return pemPrivate;
}


const getCA_P12_PubKey = async ( uid, filePath, pass ) => {
    // Read file in binary contents
    console.log("loadCA_P12Cert001: " + filePath);
    var p12 = fs.readFileSync(filePath);
    console.log("loadCA_P12Cert002: ");
    // const file = fs.readFileSync('file.pfx');
    const p12Der = forge.util.decode64(p12.toString('base64'));
    const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pass);
    const { key } = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
		const pemPublic = forge.pki.publicKeyToPem(key);
		console.log(pemPublic);
		//DUMP_PRIVATE_KEY = pemPrivate;
		return pemPublic;
}


var store = JWK.createKeyStore();
	async function creJWTJWE (uid, path, pass, req, res, next) {
		await store.generate("RSA",2048,{alg:"RS256", key_ops:["sign", "decrypt", "unwrap"]});
		lkey = (await store.get());
		JSON.stringify(lkey.toJSON(true));
		var key = lkey.toJSON();
		key.use = "verify";
		key.key_ops=["encrypt","verify", "wrap"];
		var pubKey = await JWK.asKey(key);
		console.log("pubkey:  " + JSON.stringify(pubKey));
		await store.add(pubKey);
		JSON.stringify(pubKey.toJSON());
		key = null;
		pubkey = null;
		var dt = new Date();
		var exp = new Date(dt.getTime() + (20 * 60 * 1000));
		
		var payload = 
		{
		"nameid":"240820080175",
		"activityid":"a8f769d0-a129-4ad0-8fe9-5bc7761d0331",
		"authmethod":"ATN",
		"decision":"5556",
		"month":"11",
		"day":"19",
		"year":"1982",
		"role":"User",
		"nbf":Math.floor((dt.getTime() / 1000)),
		"exp":Math.floor(exp.getTime() / 1000),
		"iat":Math.floor((dt.getTime() / 1000)),
		"iss":"http://localhost:50191",
		"aud":"http://localhost:50191"
		};
		
		var token = await JWS.createSign({format: 'compact'}, lkey).update(JSON.stringify(payload), "utf8").final();
		
		skey = await JWK.asKey(
				{"kid":"qQ1hDBdtvgbtXziPRmT09XS-6oc3vugIvkHdd8Kh1rk","kty":"RSA","key_ops":["encrypt","verify","wrapKey"],"n":"vuxR5sMnOz8LUCx-8zO6MexL8s_VA1t8FIh4_eUFgebQkyCvxHvQjTtHsqExWg_rJH_qyo3_EXK5lZXbRDbXN8TTwsDs79SrDqf3NoLLSMjGe3fS97HObP1WEcy0mFUDDlvz8Cdq0jXLnrvLKx5G_Pfz52NoGa3R5Gp8KrljeOqkd0DuV5qPtPc-EBkRhjnjH_IVsBeZ3gYGW8m6GqnREtK0lHvBTcdTUgQZZUHHzbpTv6Ta1ZQbImzDCuWBzlHQqbf8Zr6hb75rYTvfpS0NHD7WOjJBQn0PPxS0FSbZOd7ns3ZwbxAfzOwi7IoIGOl62GFxmowwnRAuJNpfkHkDxQ","e":"AQAB","alg":"RSA-OAEP","use":"enc"});
		console.log("SecretKey:   " + JSON.stringify(skey));
		var options = 
		{
		    zip: false,
		    compact: true,
		    contentAlg: contentAlg,
		    protect: Object.keys(
		    {
		      "alg": skey.alg,
		      "kid": skey.kid,
		      "enc": contentAlg
		    }),
		    fields: 
		    {
		      "alg": skey.alg,
		      "kid": skey.kid,
		      "enc": contentAlg
		    }
		};
		
		token  = await JWE.createEncrypt(options, skey).update(token, "utf8").final();
		console.log(token);
	}
	
	/*
	 * 
	 */
	
	async function creJWTJWS (uid, path, pass, req, res, next) {
		var privatepem = await getCA_P12_PrivKey(uid, './rsa_domain/'+uid+'_'+uid+'.p12', pass);
		var jwks = await fs.readFileSync(path+uid+'_x5cjwks.json');
		//console.log("jwks:  " + jwks.toString());
		const keyStore = await JWK.asKeyStore(jwks.toString());
		var privatekey = await keyStore.add(privatepem, 'pem');
		var kstore = JSON.parse(jwks.toString());
		var x5cChain = kstore.keys[2].x5c[0];
		// and signing options
		let signoptions = { fields: { x5c: x5cChain} }
		//console.log("x5c:  " + key[2].x5c[0]);
		// the message body
		var dt = new Date();
		var exp = new Date(dt.getTime() + (20 * 60 * 1000));
		let message = await getX509Details('karan123456', x5cChain, 'password');
	    // sign 'message' with the 'privatekey', include the 'x5c' chain in the headers
	    var signed;
	    var token = await JWS.createSign(signoptions, privatekey).update(message, 'utf8').final();
	    // build the jwt/jws
	    var tok_parts = JSON.stringify(token);
	    var tokParsed = JSON.parse(tok_parts);
	    var payld = tokParsed.payload;
	    var prot = 'protected';
	    var head = tokParsed.signatures[0].signature;
	    var head1 = tokParsed.signatures[0].protected;
	    var tokMain = head1+'.'+payld+'.'+head;
	    console.log(tokMain); //.startsWith('protected:' ));
	    fs.writeFileSync('./user_jwtokens/'+uid+"_x5jwtok.jwt", tokMain, null, '  ');
	    return tokMain;
	}
	
	// Utils taken from (MIT licensed):
	// https://github.com/hildjj/node-posh/blob/master/lib/index.js
	function cert_to_x5c (cert, maxdepth) {
	  if (maxdepth == null) {
	    maxdepth = 0;
	  }
	  /*
	   * Convert a PEM-encoded certificate to the version used in the x5c element
	   * of a [JSON Web Key](http://tools.ietf.org/html/draft-ietf-jose-json-web-key).
	   *             
	   * `cert` PEM-encoded certificate chain
	   * `maxdepth` The maximum number of certificates to use from the chain.
	   */

	  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
	  cert = cert.replace(/(\r\n|\n|\r)/gm, "");
	  cert = cert.split(',').filter(function(c) {
	    return c.length > 0;
	  });
	  if (maxdepth > 0) {
	    cert = cert.splice(0, maxdepth);
	  }
	  return cert;
	}

	function x5c_to_cert (x5c) {
	  var cert, y;
	  cert = ((function() {
	    var _i, _ref, _results;
	    _results = [];
	    for (y = _i = 0, _ref = x5c.length; _i <= _ref; y = _i += 64) {
	      _results.push(x5c.slice(y, +(y + 63) + 1 || 9e9));
	    }
	    return _results;
	  })()).join('\n');
	  return ("-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----");
	}
	
	
	// read this: https://www.toptal.com/web/cookie-free-authentication-with-json-web-tokens-an-example-in-laravel-and-angularjs
	
	exports.creJWTJWE = creJWTJWE;
	exports.creJWTJWS = creJWTJWS;
	exports.getX509Details = getX509Details;
	
	//creJWTJWE (uid, path, req, res, next);
	//var x5Str = 'MIID9zCCAt+gAwIBAgIBATANBgkqhkiG9w0BAQUFADB2MRQwEgYDVQQDEwtrYXJhbjEyMzQ1NjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRMwEQYDVQQKEwpQaGFkbmlzSW5jMRQwEgYDVQQLEwtrYXJhbjEyMzQ1NjAeFw0yMTA2MDIyMjU0NTdaFw0yMjA2MDIyMjU0NTdaMHYxFDASBgNVBAMTC2thcmFuMTIzNDU2MQswCQYDVQQGEwJVUzERMA8GA1UECBMIVmlyZ2luaWExEzARBgNVBAcTCkJsYWNrc2J1cmcxEzARBgNVBAoTClBoYWRuaXNJbmMxFDASBgNVBAsTC2thcmFuMTIzNDU2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8YyQ76+HorWcS6b6R9xLkChRAnVhTvxL1+hxCPsF7z4370nowOLbWHdCMrc9nU/+qKO6cWr2+gfb/JjBN6cSP43Cc8XyvX5M8F0A97gmNeWkUMWNp0nU11vu4qpiB+Gn2JN9CctWYsyqbADxRw0B2X4qKsb7KSooGhoRdc2Dz6lDv4PZLMKDRMvxcW4yTjW/hNUvPvnQyxWg7Ouz5LGJqW/o2MsuZewmeluy8Qjzv1B+X6QFK90jfXHQFmYWHgMwNPqYKn5eSQEPxqc7AA7pflB4hxZvauZojI/nioUpfFXHwG4wCHFOdQeb6KGg919GlKggp20IQIttscNG+jGYEQIDAQABo4GPMIGMMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgL0MDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDAyBgNVHREEKzAphidodHRwczovL3d3dy5wcmF0aGFtZXNoLXBoYWRuaXMuY29tOjQ0NC8wDQYJKoZIhvcNAQEFBQADggEBAJRmrvG6bVVJg5oqF+IJdN3/MgbWVUzgASZJf9tleYW5oi2e/zEaFdFu/8bL5b97JgJHc8T5QafnvNAUmaPTpul+Jw5G6uJ/k7E3LQtL3kxCl8lFyrfef4+Zv5BiuEsuK6FxvKd4KPW6Xodg3dFIJh/mELo+Nu+sUJXg/MIC3XvHeUUAshLme6i/nBLvfkdDu9wjnvAG4Owmap7ln1lSEVJAoHf5dSd2+3A8ZwyIWizX5bnFpmh2T/kze404NszrBWjbZPdLd55VbI3Qp1pEHWCagd1JMqn/JKF7GxTdmxZE2bxkEZOBYL3lqm8JJdnXP96dc585fAhw5zNlpFDw1dE=';
	creJWTJWS ('OktaUser', './JWKSets/', 'OktaUser', '', '', '');
	//getX509Details('karan123456', x5Str, 'password');