/**
 * http://usejsdoc.org/ This module is a utility for generating jwks and
 * endpoints for jwk verifier for clients This module is based on:
 * https://sometimes-react.medium.com/jwks-and-node-jose-9273f89f9a02
 * A good explaination is in link below:
 * https://medium.com/nerd-for-tech/jwt-jws-and-jwe-in-nodejs-7595542565d0
 */
const fs = require('fs');
const fsBase = require('fs');
const path = require('path');
const fsp = fsBase.promises
const jose = require('node-jose');
const forge = require("node-forge");
const {JWK, JWE, parse } = require("node-jose");
const { generateKeyPair, createPublicKey } = require('crypto'); // native
var pemJWKS = require('./com.utes.pem-to-jwks');

ksVals = {
		CustomerId: '',
		Timestamp: '',
		xks: '',
		stdks: '',
};

//const pem2jwk = require("./com.utes.pem-to-jwks");
/**
 * you don’t need to add null and ‘empty-space’ as 2nd and 3rd argument
 * for the JSON stringify but I really like to keep my files readable 
 * for the human eye, and I’m passing the true to the toJSON(true) 
 * method, because this flag will return the public but also the 
 * private section of the asymmetric key and we will use the 
 * private key later to sign the token
 * 
 * @returns
 */
var keyStore = '';
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

	
	const getCA_P12_PrivKey = async ( uid, filePath, pass ) => {
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
			//DUMP_PRIVATE_KEY = pemPrivate;
			return pemPrivate;
	}
	
	
	const getCA_P12_PubKey = async ( uid, filePath, pass ) => {
	    // Read file in binary contents
	    console.log("loadCA_P12Cert001: ");
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
	
	function cert_to_x5c (cert, maxdepth) {
		console.log("Cert1:  " + cert);
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
	  cert = cert.toString();
	  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
	  cert = cert.split(',').filter(function(c) {
	    return c.length > 0;
	  });
	  if (maxdepth > 0) {
	    cert = cert.splice(0, maxdepth);
	  }
	  console.log("Cert2:  " + cert);
	  return cert;
	}

	async  function createstdJWKStore (uid, path, pass) {
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    let keystore = JWK.createKeyStore();
	    await keystore.add(jwKeys[0]);
	    await keystore.add(jwKeys[1]);
		//keyStore.then(result => {
	    ksVals.stdks = JSON.stringify(keystore.toJSON(true));
		  fs.writeFileSync('./JWKSets/'+uid+'_stdjwk.json', JSON.stringify(keystore.toJSON(true), null, '  '));
		//});
	}
	
	async function getJWKStore (uid, path, req, res, next)  {
		  const {promises: {readFile}} = require("fs");
		  readFile('./JWKSets/'+uid+'_pem2jwks.json').then(fileBuffer => {
		    // console.log(fileBuffer.toString());
			  var keystore = jose.JWK.asKeyStore(fileBuffer.toString());
			  keyStore = fileBuffer.toString();
			console.log("Ajeet:  " + keyStore);
			keyStore = keystore;
			return keystore;
		  }).catch(error => {
		    console.error(error.message);
		    process.exit(1);
		  });
	}
	
	async function loadKeyStore1(uid, path, req, res, next) {
	    const data = await fs.readFile('./JWKSets/keys.json');
	    var keystore = jose.JWK.asKeyStore(data.toString());
	    console.log("Ajeet:  " + data);
	    return new Buffer(keystore);
	}
	
	const loadKeyStore = async (uid, path, req, res, next) => {
		const data = await fsp.readFile(path);
	    // console.log(data.toString());
	    var keys = await jose.JWK.asKeyStore(data.toString()).
	     then(function(result) {
	    	 console.log(keys);
	       // {result} is a jose.JWK.KeyStore
	       keyStore = result;
	       console.log(JSON.stringify(result));
	       return keyStore;
	     });
	   
	  }
	
	
	// This function is used by /jwks endpoint.
	const getJWKPublic = async (uid, path, req, res, next) => {
		const ks = fs.readFileSync('./JWKSets/'+uid+'_pem2jwks.json');
		const keyStore = await jose.JWK.asKeyStore(ks.toString());
		return (keyStore.toJSON());
	}	
	
	const createJWToken1 = async (uid, path, req, res, next) => {
		var key = fs.readFileSync(path+uid+'_prvKey.pem');

		var serviceAccountId = uid;
		var keyId = '0987654321';
		var now = Math.floor(new Date().getTime() / 1000);

		var payload = { aud: "https://iam.api.cloud.yandex.net/iam/v1/tokens",
		                iss: serviceAccountId,
		                iat: now,
		                exp: now + 3600 };

		jose.JWK.asKey(key, 'pem', { kid: keyId, alg: 'RS256' })
		    .then(function(result) {
		        jose.JWS.createSign({ format: 'compact' }, result)
		            .update(JSON.stringify(payload))
		            .final()
		            .then(function(result) {
		                // result
		            	console.log("Result: " + result);
		            	fs.writeFileSync('./user_jwtokens/'+uid+"_jwtok.jwt", result, null, '  ');
		            });
		    });
	}	
	
	async function createJWKStore (uid, path, pass, req, res, next) {
		const keyStore = jose.JWK.createKeyStore();
		console.log("createJWKStore:001");
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_'+uid+'.p12', pass);
		//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_'+uid+'.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    //let keystore = JWK.createKeyStore();
	    await keyStore.add(jwKeys[0]);
	    await keyStore.add(jwKeys[1]);
	    console.log("createJWKStore:001");
		fs.writeFileSync('./JWKSets/'+uid+'_pem2jwks.json', JSON.stringify(keyStore.toJSON(true), null, '  '));
	}
	
	async  function createstdJWKStore (uid, path, pass) {
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_'+uid+'.p12', pass);
		//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_'+uid+'.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    let keystore = JWK.createKeyStore();
	    await keystore.add(jwKeys[0]);
	    await keystore.add(jwKeys[1]);
		//keyStore.then(result => {
		  fs.writeFileSync('./JWKSets/'+uid+'_stdjwks.json', JSON.stringify(keystore.toJSON(true), null, '  '));
		//});
	}	
	
	 async function x5jwtsjson (uid, path, pass) { 
		 var cert = await fs.readFileSync('./rsa_domain/'+uid+'_DOMAINCert.pem');
		 //derCrt = await fs.readFileSync('./CERTIFICATE.der');
		 //derCrt = derCrt.toString().replace('r ' , '');
		 cert = cert.toString();
		 cert1 = cert.replace('-----BEGIN CERTIFICATE-----\r\n', '');
		 cert1 = cert1.replace('\r\n-----END CERTIFICATE-----\r\n', '');
		 cert1 = cert1.replace(/(\r\n|\n|\r)/gm, "");
		 //console.log("Cert1:  " + cert);;
		 var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_'+uid+'.p12', pass);
			//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
			//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
			var pubk = await getCA_P12_PubKey(uid, path+uid+'_'+uid+'.p12', pass);
			const jwKeys = await Promise.all([
		        JWK.asKey(prvKey, "pem"),
		        JWK.asKey(pubk, "pem"),
		        ]);
		    let keystore = JWK.createKeyStore();
		    await keystore.add(jwKeys[0]);
		    await keystore.add(jwKeys[1]);
		    await keystore.add(cert, 'pem');
		    var kdata = JSON.stringify(keystore);
		    var pdata = JSON.parse(kdata);
		    pdata.keys[2]['x5c'] = [cert1];
		    JSON.stringify(pdata);
		    ksVals.xks = JSON.stringify(pdata);
		    //await keystore.add(derCrt, 'x509');
		    //console.log("x5jwtsjsonkey:  " + JSON.stringify(pdata));
		    fs.writeFileSync('./JWKSets/'+uid+'_x5cjwks.json', JSON.stringify(pdata), null, '  ');
	 }
	
	
	// This function is used by /token endpoint
	const createJWToken = async (uid, path, req, res, next) => {
		const ks = fs.readFileSync('./JWKSets/'+uid+'_pem2jwks.json');		
		const keyStore = await jose.JWK.asKeyStore(ks.toString());
		const [key] = keyStore.all({ use: 'sig' });		  
		const opt = { compact: true, jwk: key, fields: { algorithms: 'RSA', typ: 'jwt' } }
		const payload = JSON.stringify({
			exp: Math.floor((Date.now() +24*60*60*1000) / 1000),
			iat: Math.floor(Date.now() / 1000),
			sub: 'Ajeet',
		 });
		  const token = await jose.JWS.createSign(opt, key).update(payload, "utf8").final();
		  //res.send({ token })
		  fs.writeFileSync('./user_jwtokens/'+uid+"_jwtok.jwt", token, null, '  ');
	}
	
	//This function is used by /validateToken endpoint
	const validateToken = async (path, req, res) => {
		const { token } = req.body;
		const { data } = await axios.get('http://localhost:4040/jwks');
		const [ firstKey ] = data.keys;
		const publicKey = jwktopem(firstKey);
		try {
			const decoded = jwt.verify(token, publicKey)
		    res.send(decoded)
		} catch (e) {
		    res.send({ error: e })
		}
	}	
	
	//This function able to sign JWTs with a different 
	//key but also allow the clients that have previously 
	//signed JWTs to verify with the help of the /jwks 
	//endpoint and after all the clients can’t possibly 
	//have an old token (after 24h given the expiration 
	//time that we set) we will delete the unused key
	//used by /addKey endpoint
	const addJWK2KeyStore = async (path, req, res) => {
		const ks = fs.readFileSync(path);
		const keyStore = await jose.JWK.asKeyStore(ks.toString());
		await keyStore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' });
		const json = keyStore.toJSON(true);
		json.keys = json.keys.reverse();
		fs.writeFileSync('keys.json', JSON.stringify(json, null, '  '));
	}	
	
	//This function now implements the delete key portion 
	//(we should trigger that after the maximum time 
	//that we apply to the tokens in our case 24h) 
	//all we need is plain JS but I’ll use a little 
	//bit of node-jose just to return the result and 
	//check that is working. Used by /delKey endpoint.
	
	const delJWKFromKeyStore = async (path, req, res) => {
		const ks = JSON.parse(fs.readFileSync(path));
		if (ks.keys.length > 1) ks.keys.pop();
		fs.writeFileSync('keys1.json', JSON.stringify(ks, null, '  '));
		const keyStore = await jose.JWK.asKeyStore(JSON.stringify(ks));
	}
	
	
	const crJWKFromPrivateKeyPEM1 = async (uid, path, req, res, next) => {
		//const prvKey = fs.readFileSync(path);
		//const prvKey = readFile(path, '');
		// Parse PEM-encoded key to RSA public / private JWK
		//var jwkk = JWK.parseFromPEMEncodedObjects(prvKey);
		//console.log(JSON.stringify(jwkk));
		pem2jwk.pem2jwks(uid,  path+uid+'_selfsigned.crt', 'password', req, res, next);
	}
	
	// function does not work.
	const crJWKFromPrivateKeyPEM = async (uid, path, pass, req, res, next) => {
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubKey = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		// Parse PEM-encoded key to RSA public / private JWK
		var jwkk = JWK.parseFromPEMEncodedObjects(prvKey);
		console.log(JSON.stringify(jwkk));
	}
	
	// good examples:
	// https://stackoverflow.com/questions/48659883/how-to-generate-encrypted-jwe-with-node-jose
	// follow this example:
	// https://techdai.info/how-to-create-and-verify-jwt-tokens-via-jwk-endpoints-for-your-microservices-in-node-js/
	// https://techdai.info/how-to-create-and-verify-jwt-tokens-via-jwk-endpoints-for-your-microservices-in-node-js/
	// https://sometimes-react.medium.com/jwks-and-node-jose-9273f89f9a02
	// Implemented code from below link:
	// https://medium.com/nerd-for-tech/jwt-jws-and-jwe-in-nodejs-7595542565d0
	var encrypt = async (raw, pubk, format = 'compact', contentAlg = "A256GCM", alg = "RSA-OAEP") => {	    
	    let publicKey = await JWK.asKey(pubk, "pem");
	    const buffer = Buffer.from(JSON.stringify(raw))
	    const encrypted = await JWE.createEncrypt({ format: format, contentAlg: contentAlg, fields: { alg: alg } }, publicKey)
	        .update(buffer).final();
	    return encrypted;
	}
	

	var decrypt = async (encryptedBody, prvk) => {
	    //let _privateKey = 
	    let keystore = JWK.createKeyStore();
	    await keystore.add(await JWK.asKey(prvk, "pem"));
	    let outPut = parse.compact(encryptedBody);
	    let decryptedVal = await outPut.perform(keystore);
	    let claims = Buffer.from(decryptedVal.plaintext).toString();
	    return claims;
	}
	
	
	
	/*
	 * JWE is the standard way of encrypting claims of the JWT token. 
	 * The code segments explain how to load keys, encrypt the token, 
	 * and decrypt the token. These codes are written in node js using 
	 * the cisco node-jose library.
	 * The node-jose library provides a JWK namespace to generate, import, 
	 * and export keys. In this example, an asymmetric key pair is 
	 * used to encrypt the payload.
	 * Key pairs are generated for any logged-in user already.
	 */
	
	const crJWEToken = async (uid, pass, path, req, res, next) => {
		//var prvKey = fs.readFileSync(path+uid+'_prvKey.pem');
		var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_certp12b64.p12', pass);
		//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
		//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
		var pubk = await getCA_P12_PubKey(uid, path+uid+'_certp12b64.p12', pass);
		const jwKeys = await Promise.all([
	        JWK.asKey(prvKey, "pem"),
	        JWK.asKey(pubk, "pem")
	    ]);
	    let keystore = JWK.createKeyStore();
	    await keystore.add(jwKeys[0]);
	    await keystore.add(jwKeys[1]);
		let raw = {
			    "mobileNumber": "1234567890",
			    "customerId": uid,
			    "sessionId": "3a600342-a7a3-4c66-bbd3-f67de5d7096f",
			    "exp": 1645544094,
			    "jti": "f3902a08-0e24-4dcc-bed1-f4cd9611bfad"
			};
			var encJwe = await encrypt(raw, pubk);
			//var encJwe = await encrypt(raw, prvKey);
			console.log("Encrypted JWE:  " + encJwe);
			var decJwe = await decrypt(encJwe, prvKey);
			//var decJwe = await decrypt(encJwe, pubk);
			console.log("Decrypted JWE:  " + decJwe);
	}
	

	// Helper
	// taken from (MIT licensed):
	// https://github.com/hildjj/node-posh/blob/master/lib/index.js
	function cert_to_x5c (cert, maxdepth) {
		console.log("Cert1:  " + cert);
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
	  cert = cert.toString();
	  cert = cert.replace(/-----[^\n]+\n?/gm, ',').replace(/\n/g, '');
	  cert = cert.split(',').filter(function(c) {
	    return c.length > 0;
	  });
	  if (maxdepth > 0) {
	    cert = cert.splice(0, maxdepth);
	  }
	  console.log("Cert2:  " + cert);
	  return cert;
	}
	
	 async function jwtsjson (uid, path, pass) {
		 var cert = await fs.readFileSync('./rsa_domain/'+uid+'_DOMAINCert.pem');
		 cert = cert.toString();
		 cert1 = cert.replace('-----BEGIN CERTIFICATE-----', '');
		 cert1 = cert1.replace('-----END CERTIFICATE-----', '');
		 //console.log("Cert1:  " + cert);;
		 var prvKey = await getCA_P12_PrivKey(uid, path+uid+'_'+uid+'.p12', pass);
			//var pubKey = fs.readFileSync(path+uid+'_selfsigned.crt');
			//var pubKey = readFile(path+uid+'_selfsigned.crt', 'utf-8');
			var pubk = await getCA_P12_PubKey(uid, path+uid+'_'+uid+'.p12', pass);
			const jwKeys = await Promise.all([
		        JWK.asKey(prvKey, "pem"),
		        JWK.asKey(pubk, "pem"),
		        ]);
		 //console.log("Cert1:  " + cert);
		 const keystore = jose.JWK.createKeyStore();
		 const output = keystore.toJSON();
		 keystore.toJSON(true);

		 jose.JWK.asKeyStore(keystore).then(result => { 
			 keystore.add(jwKeys[0]);
			 keystore.add(jwKeys[1]);
			 keystore.add(cert, 'pem');
			 console.log("keystore:  " + JSON.stringify(result))});

		 let key = keystore.get('kid');

		 key = keystore.get('kid', { kty: 'RSA' });

		 // ... and by 'use'
		 key = keystore.get('kid', { use: 'enc' });

		 // ... and by 'alg'
		 key = keystore.get('kid', { alg: 'RSA-OAEP' });

		 // ... and by 'kty' and 'use'
		 key = keystore.get('kid', { kty: 'RSA', use: 'enc' });

		 // same as above, but with a single {props} argument
		 key = keystore.get({ kid: 'kid', kty: 'RSA', use: 'enc' });

		 let everything = keystore.all();

		 // filter by 'kid'
		 everything = keystore.all({ kid: 'kid' });

		 // filter by 'kty'
		 everything = keystore.all({ kty: 'RSA' });
			 
	 }
	 
	 async function createJWKS(uid, path, pass, req, res) {
					 console.log("getJWKS:  " + uid);
					 pemJWKS.pem2jwks (uid, path, pass, '','','');
					 await createstdJWKStore(uid, path, pass);
			 		 await x5jwtsjson(uid, path, pass);
			 		//ksVals.CustomerId =  req.app.session.clnt;
		}
	 
	exports.createJWKStore = createJWKStore;
	exports.getJWKStore = getJWKStore;
	exports.loadKeyStore = loadKeyStore;
	exports.keyStore = keyStore;
	exports.createJWKS = createJWKS;
	exports.crJWKFromPrivateKeyPEM = crJWKFromPrivateKeyPEM;
	exports.createstdJWKStore = createstdJWKStore;
	exports.x5jwtsjson = x5jwtsjson;
	exports.getJWKPublic = getJWKPublic;
	exports.createJWToken = createJWToken;
	exports.crJWEToken = crJWEToken;
	// function call below creates JWKS in JWKSets directory
	//createJWKStore('karan123456', './user_certs/', 'password', '', '', '');
	// function call below creates JWT in user_jwtokens director
	//createJWToken('karan123456', './user_jwks/', '', '', '', '');
	
	//var ret = getJWKStore('', '');
	//var ret = loadKeyStore('./JWKSets/keys.json', '', '').then(console.log("KeyS:   " +  keyStore));
	//var prvKey = crJWKFromPrivateKeyPEM('karan123456', './user_certs/', 'password', '', '', '');
	//getJWKPublic('karan123456', './user_jwks/', '', '', '', '');
	//createJWToken('karan123456', './user_certs/', '', '', '', '');
	//var pubk = getCA_P12_PrivateKey('karan123456', './user_certs/'+'karan123456'+'_certp12b64.p12', 'password');
	//console.log("pubkey:  " + JSON.stringify(pubk));
	
	// function below encrypts and decrypts a JWT
	//createstdJWKStore('OktaUser', './rsa_domain/', 'OktaUser');
	/*crJWEToken('karan123456', 'password', './user_certs/', '', '', '', '');*/
	//x5jwtsjson('OktaUser', './rsa_domain/', 'OktaUser');
	//getJWKS('OktaUser', './rsa_domain/', 'OktaUser', '', '', '');