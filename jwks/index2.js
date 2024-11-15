const jwtHeler = require("./com.utes.jwks.createJWKSNew");
const fs = require('fs');
var forge = require('node-forge');

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

async function cre_pem2jwt(uid, prvkeyFile, certFile, usrdata, req, res, next) {
	var prvKey = getCA_P12_PrivateKey (uid, prvkeyFile , 'password' );
	await jwtHeler.createKeystore(prvKey);
    const payload = {
        iss: 'idp.utes.com, sub: karan123456, aud: https://utes.com/saml, nbf: 1622511247.388, iat: 1622511247.388, exp: 1622597647'
    };
    await jwtHeler.createKeystore();
    const publicJWK = await jwtHeler.createPublicJWK();
    const privateJWK = await jwtHeler.createPrivateJWK();
    const token = await jwtHeler.createJWT(payload);
    const result = await jwtHeler.verifyJWT(token, publicJWK);

    console.log("public jwk :: ", JSON.stringify(publicJWK));
    console.log("\n");
    console.log("private jwk :: ", JSON.stringify(privateJWK));
    console.log("\n");
    console.log("token :: ", token);
    console.log("\n");
    console.log("payload :: ", result.payload.toString());

}
exports.cre_pem2jwt = cre_pem2jwt;
cre_pem2jwt('karan123456', './user_certs/karan123456_certp12b64.p12', './user_certs/karan123456_selfsigned.crt', '', '', '', '');