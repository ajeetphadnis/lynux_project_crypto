// https://codebun.com/login-registration-nodejsexpress-mongodb/

const mongoose = require("mongoose");
var crypto = require('crypto');

const ClientSchema = new mongoose.Schema({
    clientId:String,
    clientPw:String,
    commonName:String,
    countryName:String,
    ST:String,
    localityName:String,
    organizationName:String,
    OU:String,
    keySize:String,
    passphrase:String,
    p12FileName:String,
	hash : String,
	salt : String
}) ;

//Method to set salt and hash the password for a user
ClientSchema.methods.setPassword = function(clientPw) {

    // Creating a unique salt for a particular user
    this.salt = crypto.randomBytes(16).toString('hex');

    // Hashing user's salt and password with 1000 iterations,

    this.hash = crypto.pbkdf2Sync(clientPw, this.salt, 1000, 64, `sha512`)
	    .toString(`hex`);
};

// Method to check the entered password is correct or not
ClientSchema.methods.validPassword = function(clientPw) {
	console.log("validPassword001: " + clientPw);
    var hash = crypto.pbkdf2Sync(clientPw, this.salt, 1000, 64, `sha512`)
	    .toString(`hex`);
    console.log("validPassword002: " + hash  + "    compare:   " + this.hash === hash);
    return this.hash === hash;
};

//ClientSchema.plugin(passportLocalMongoose, {usernameField: "clientId"});
//ClientSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model("Client",ClientSchema);
