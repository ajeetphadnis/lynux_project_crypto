const jose = require('node-jose');
var forge = require('node-forge');
const fs = require('fs');

const args = process.argv.slice(2);

//const key = fs.readFileSync(args[0]);
const keystore = jose.JWK.createKeyStore();

var DUMP_PRIVATE_KEY1 = '-----BEGIN PRIVATE KEY-----'+
'MIIEpAIBAAKCAQEA1xM1K4M+H8lD6/9L+TpNfRgByL0cNYLI2Oa47gzUN6h11ayp'+
'jNPbaMwXUZ6Hnezia6X1PQCmg9ChmUvuhS1BeB/jM07YuAOLLHIDVtnBbisceVoH'+
'RciPdopsMdJsg2J6VVeZsoX3rq5m22ZPVzwHAsaKu1VoxYWK4gH/BBsPR6D2bAl3'+
'rx8Xyi4zBFkOt78kBYNYmh7AmIBhomdDwNxkCosMQA0sRE6ls7Gwihn/cMo4k3Md'+
'ddqMIvk/IC0FO0iwdHTnj2N6SMkjHmn0IBtl1r/Xlw7D55SGdBvb2R0nWOCZW+5O'+
'oFTO1u1f14BZOox5Temk9hjxKhckcHCylnSztwIDAQABAoIBADeKQkTGU5ipxNyA'+
'xQHLSI9xT6SjEVHQQEWi70aqEXN+EU/okrBHVXWunqb5JVRnA+GArd/e9yE7E0Af'+
'F61Ujn+S3H03c0exwpLrrmkTOpxUjbnYweAHduTJwj7rdBJJsAWx5YLwjZGSgAVQ'+
'WlTQr47L7q+J0tCPN9o9YbmRs1Rvhxnrik35GM/iese6cknnfMyXprHmEQXX9+F5'+
'UEWuW0URa1gEEBVoavSidSNYpYFfo7tNvqvZwemW+GDosgOwlhIJnmSdcQZXQDxI'+
'YBjgNVTTgUPl1p2Ih8FtXe0z1z7ZuEU0vpHV29WZdYAxpuMpGeBrWA7cjbGwyl7g'+
'u4TipWECgYEA/rmpMesbZQmOwLW9BQHcPchKAkSELiZNheGOWbCNN8H+PKQyc2a5'+
'UqswLOPGBVpPJXsSK2QB5cJpUeFso5emBC/iCZzWpCbcMd6W53HZX77XA1P8gU1H'+
'NFtDL8YxMiTMVjIjdfcX9QoyRniicjZSRrG0ihquNmJr9xwXvSOntSUCgYEA2Ca/'+
'zsnVAZOeA7rGe4Q+pVCzNOlobddo7KxRWtyY+cUPf0vA8fX1pOGzSKEY+Itrz3c6'+
'vI73PTpepS8+6lDietr+7H7dlj3gBANesO9bhhul8EkDs2UhX73joiwvt7BX688j'+
'rBb9HOiqO0oQzTqPzDYdnxbihc2ugQOV+Q3npKsCgYEAh1kRnROm58XvU1h+ClYV'+
't8JgCNptPbReht/16pRURSdQNtqscANKP7H0lDWnN5rn6St+2Q13sKTfn4FfX4Gp'+
'1hm3SpJKvshjQiBbILmu3iAiUYNj7TSpvBkuFwmBhHpnFPnpO7pCwZJcanOZJYTV'+
'rPipzKQmo4EiixgjSP3UE/0CgYBAdz4ZlISc1cP45MmxqP1uHKV2EG7+45H9lF8n'+
'NEfDpow6sQM4pty+cjogXTuvVRWwaKTx+8mtTy1PIsom5DzH22zQZ/36gzW+vKqP'+
'JrQrSS+yfHRIGs9bWKz9fyQ0KrnuMHc5KhoPdyzeRfbA3shoZXNsMU0aDwAOpl0i'+
'TI1bxQKBgQDYHjFXdgR3bQNsEXymxNv/Uo02Su26lxx+Fxb3DfHkZU6PK6P8vIgs'+
'+rrc66xZG7TifcMvIPBVjL7/funSUpn0auZtVL7SwfXi8or33wMYX+XuRKkh1WFW'+
'kFUYj3e8y6SeIgX0IxPgTrhM6FPm87ZCEKVZShJWc+2dtGBEOKRpJg=='+
'-----END PRIVATE KEY-----';

	function getCA_P12_PrivateKey ( uid, filePath, pass ) {
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


	async function pem2jwks (uid, filjwt, pass, req, res, next) {
		DUMP_PRIVATE_KEY = getCA_P12_PrivateKey (uid,  filjwt+uid+'_'+uid+'.p12', pass );
		let rawdata = fs.readFileSync(filjwt+uid+'_'+'DOMAINCert.pem', 'utf8');
		keystore.add(rawdata, 'pem').then(function(_) {
		    const jwks = keystore.toJSON(DUMP_PRIVATE_KEY);
		    var jwk = JSON.stringify(jwks, null, 4);
		    global.jwstr = jwk;
		    console.log("pem2jwks001:      " + jwk);
		    fs.writeFile("./JWKSets/"+uid+"_pem2jwks.json", jwk, function(err) {
				if(err) {
			        return console.log(err);
			    }
				return jwk;
		    })//.catch(err => { console.log(err);
		    return jwk;
		  });
	};
	//}
exports.pem2jwks = pem2jwks;
exports.getCA_P12_PrivateKey = getCA_P12_PrivateKey;
// getCA_P12_PrivateKey ('karan123456',  './user_certs/'+'karan123456'+'_certp12b64.p12', 'password' );
pem2jwks ('OktaUser',  './rsa_domain/', 'OktaUser', '','','');
