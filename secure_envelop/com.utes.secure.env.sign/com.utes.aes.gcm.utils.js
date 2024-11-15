window.crypto.subtle.generateKey(
    {
        name: "AES-GCM",
        length: 256, //can be  128, 192, or 256
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
)
.then(function(key){
    //returns a key object
    console.log(key);
})
.catch(function(err){
    console.error(err);
});


window.crypto.subtle.importKey(
	    "jwk", //can be "jwk" or "raw"
	    {   //this is an example jwk key, "raw" would be an ArrayBuffer
	        kty: "oct",
	        k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
	        alg: "A256GCM",
	        ext: true,
	    },
	    {   //this is the algorithm options
	        name: "AES-GCM",
	    },
	    false, //whether the key is extractable (i.e. can be used in exportKey)
	    ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
	)
	.then(function(key){
	    //returns the symmetric key
	    console.log(key);
	})
	.catch(function(err){
	    console.error(err);
	});


window.crypto.subtle.exportKey(
	    "jwk", //can be "jwk" or "raw"
	    key //extractable must be true
	)
	.then(function(keydata){
	    //returns the exported key data
	    console.log(keydata);
	})
	.catch(function(err){
	    console.error(err);
	});


window.crypto.subtle.encrypt(
	    {
	        name: "AES-GCM",

	        //Don't re-use initialization vectors!
	        //Always generate a new iv every time your encrypt!
	        //Recommended to use 12 bytes length
	        iv: window.crypto.getRandomValues(new Uint8Array(12)),

	        //Additional authentication data (optional)
	        additionalData: ArrayBuffer,

	        //Tag length (optional)
	        tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
	    },
	    key, //from generateKey or importKey above
	    data //ArrayBuffer of data you want to encrypt
	)
	.then(function(encrypted){
	    //returns an ArrayBuffer containing the encrypted data
	    console.log(new Uint8Array(encrypted));
	})
	.catch(function(err){
	    console.error(err);
	});


window.crypto.subtle.decrypt(
	    {
	        name: "AES-GCM",
	        iv: ArrayBuffer(12), //The initialization vector you used to encrypt
	        additionalData: ArrayBuffer, //The addtionalData you used to encrypt (if any)
	        tagLength: 128, //The tagLength you used to encrypt (if any)
	    },
	    key, //from generateKey or importKey above
	    data //ArrayBuffer of the data
	)
	.then(function(decrypted){
	    //returns an ArrayBuffer containing the decrypted data
	    console.log(new Uint8Array(decrypted));
	})
	.catch(function(err){
	    console.error(err);
	});


window.crypto.subtle.wrapKey(
	    "jwk", //can be "jwk", "raw", "spki", or "pkcs8"
	    key, //the key you want to wrap, must be able to export to above format
	    wrappingKey, //the AES-GCM key with "wrapKey" usage flag
	    {   //these are the wrapping key's algorithm options
	        name: "AES-GCM",

	        //Don't re-use initialization vectors!
	        //Always generate a new iv every time your encrypt!
	        //Recommended to use 12 bytes length
	        iv: window.crypto.getRandomValues(new Uint8Array(12)),

	        //Additional authentication data (optional)
	        additionalData: ArrayBuffer,

	        //Tag length (optional)
	        tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
	    }
	)
	.then(function(wrapped){
	    //returns an ArrayBuffer containing the encrypted data
	    console.log(new Uint8Array(wrapped));
	})
	.catch(function(err){
	    console.error(err);
	});


window.crypto.subtle.unwrapKey(
	    "jwk", //"jwk", "raw", "spki", or "pkcs8" (whatever was used in wrapping)
	    wrapped, //the key you want to unwrap
	    wrappingKey, //the AES-GCM key with "unwrapKey" usage flag
	    {   //these are the wrapping key's algorithm options
	        name: "AES-GCM",
	        iv: ArrayBuffer(12), //The initialization vector you used to encrypt
	        additionalData: ArrayBuffer, //The addtionalData you used to encrypt (if any)
	        tagLength: 128, //The tagLength you used to encrypt (if any)
	    },
	    {   //this what you want the wrapped key to become (same as when wrapping)
	        name: "AES-CBC",
	        length: 256
	    },
	    false, //whether the key is extractable (i.e. can be used in exportKey)
	    ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
	)
	.then(function(key){
	    //returns a key object
	    console.log(key);
	})
	.catch(function(err){
	    console.error(err);
	});


