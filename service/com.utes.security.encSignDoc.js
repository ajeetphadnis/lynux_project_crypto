// https://gist.github.com/sohamkamani/b14a9053551dbe59c39f83e25c829ea7
const crypto = require("crypto");
const fs = require('fs');
// The `generateKeyPairSync` method accepts two arguments:
// 1. The type ok keys we want, which in this case is "rsa"
// 2. An object with the properties of the key


	function enc_sign_Document(doc, encKeyFile, signKeyFile, req, res, next) {
        // This is the data we want to encrypt
        const data = "my secret data"
        
        const encryptedData = crypto.publicEncrypt(
        	{
        		key: publicKey,
        		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        		oaepHash: "sha256",
        	},
        	// We convert the data string to a buffer using `Buffer.from`
        	Buffer.from(data)
        )
        
        // The encrypted data is in the form of bytes, so we print it in base64 format
        // so that it's displayed in a more readable form
        console.log("encypted data: ", encryptedData.toString("base64"))
        
        const decryptedData = crypto.privateDecrypt(
        	{
        		key: privateKey,
        		// In order to decrypt the data, we need to specify the
        		// same hashing function and padding scheme that we used to
        		// encrypt the data in the previous step
        		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        		oaepHash: "sha256",
        	},
        	encryptedData
        )
        
        // The decrypted data is of the Buffer type, which we can convert to a
        // string to reveal the original data
        console.log("decrypted data: ", decryptedData.toString())
        
        // Create some sample data that we want to sign
        const verifiableData = "this need to be verified"
        
        // The signature method takes the data we want to sign, the
        // hashing algorithm, and the padding scheme, and generates
        // a signature in the form of bytes
        const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
        	key: privateKey,
        	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        })
        
        console.log(signature.toString("base64"))
        
        // To verify the data, we provide the same hashing algorithm and
        // padding scheme we provided to generate the signature, along
        // with the signature itself, the data that we want to
        // verify against the signature, and the public key
        const isVerified = crypto.verify(
        	"sha256",
        	Buffer.from(verifiableData),
        	{
        		key: publicKey,
        		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        	},
        	signature
        )
        
        // isVerified should be `true` if the signature is valid
        console.log("signature verified: ", isVerified)
	}
	
	
	function signDigDocument(doc, signType, req, res, next) {
	 // See keys/README.md on how to generate this key
	    const private_key = fs.readFileSync('./rsa_domain/Client_DOMAINprvKey.pem', 'utf-8');

	    // File/Document to be signed
	    doc = fs.readFileSync('./service/sample-doc.txt');

	    // Signing
	    const signer = crypto.createSign('RSA-SHA256');
	    signer.write(doc);
	    signer.end();

	    // Returns the signature in output_format which can be 'binary', 'hex' or 'base64'
	    const signature = signer.sign(private_key, 'base64')

	    console.log('Digital Signature: ', signature);

	    // Write signature to the file `signature.txt`
	    fs.writeFileSync('signature.txt', signature);

	}
	
	
	function verifySignature(sigFile, pubKey, req, res, next) {
	 // See keys/README.md on how to generate this key
	    const public_key = fs.readFileSync('./rsa_domain/Client_DOMAINCert.pem', 'utf-8');

	    // Signature from sign.js
	    const signature = fs.readFileSync('signature.txt', 'utf-8');

	    // File to be signed
	    const doc = fs.readFileSync('./service/sample-doc.txt');

	    // Signing
	    const verifier = crypto.createVerify('RSA-SHA256');
	    verifier.write(doc);
	    verifier.end();

	    // Verify file signature ( support formats 'binary', 'hex' or 'base64')
	    const result = verifier.verify(public_key, signature, 'base64');

	    console.log('Digital Signature Verification : ' + result);

	}
	
	
	function anotherSignExample() {
	  //Create Private Key with OpenSSL
	  //openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:3 -out privateKey.pem
	  //Generate Public Key to be used at the client side (Mobile)
	  //openssl pkey -in privateKey.pem -out publicKey.pem -pubout
	  const crypto = require('crypto')
	  const fs = require('fs')

	  const private_key = fs.readFileSync('digital_sign/privateKey.pem', 'utf-8')
	  //File to be signed
	  const package = fs.readFileSync('webpackage.zip')
	  //Signing
	  const signer = crypto.createSign('sha256');
	  signer.update(package);
	  signer.end();
	  const signature = signer.sign(private_key)
	  const buff = new Buffer(signature);
	  const base64data = buff.toString('base64');
	  console.log('Digital Signature: ' + base64data);
	  //Equivalent to openssl dgst -sha256 -sign digital_sign/privateKey.pem webpackage.zip | base64
	}
exports.enc_sign_Document = enc_sign_Document;
exports.signDigDocument = signDigDocument;
exports.verifySignature = verifySignature;
//signDigDocument('sample-doc.txt', 'RSA-SHA256', '', '', '');
verifySignature('', '', '', '', '');