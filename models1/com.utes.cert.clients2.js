// https://codebun.com/login-registration-nodejsexpress-mongodb/

const mongoose =  require("mongoose");
const passport =  require("passport");
const bodyParser  =  require("body-parser");
const LocalStrategy  =  require("passport-local");
const passportLocalMongoose =  require("passport-local-mongoose");

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
    p12FileName:String
}) ;

ClientSchema.plugin(passportLocalMongoose, {usernameField: "clientId"});
//ClientSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model("Client",ClientSchema);
