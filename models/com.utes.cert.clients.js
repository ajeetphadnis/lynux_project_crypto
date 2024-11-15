// https://codebun.com/login-registration-nodejsexpress-mongodb/
/**
 * Project: com.utes.cert.crypto
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */


const mongoose =  require("mongoose");
const passport =  require("passport");
const bodyParser  =  require("body-parser");
const LocalStrategy  =  require("passport-local");
const passportLocalMongoose =  require("passport-local-mongoose");


/**
 * 
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
var ClientSchema = new mongoose.Schema({
    clientId : {type: String, unique: true, required:true},
    clientPw: {type: String, required:false, unique:false},
    commonName: {type: String, required:false, unique:false},
    countryName: {type: String, required:false, unique:false},
    ST: {type: String, required:false, unique:false},
    localityName: {type: String, required:false, unique:false},
    organizationName: {type: String, required:false, unique:false},
    OU: {type: String, required:false, unique:false},
    keySize: {type: String, required:false, unique:false},
    passphrase: {type: String, required:false, unique:false},
    p12FileName: {type: String, required:false, unique:false}
}) ;

ClientSchema.plugin(passportLocalMongoose, {usernameField: "clientId"});
module.exports = mongoose.model("Client",ClientSchema);
