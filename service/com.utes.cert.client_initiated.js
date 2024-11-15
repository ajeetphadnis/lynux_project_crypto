//var crAssert = require('../api/com.utes.assert.samlAssertCreate');
var fs = require('fs'); 
const Clients =  require("../models/com.utes.cert.clients");
var usrDb = require('../models/com.utes.mongo.certClient.crud');
var usrStruct = require('../models/com.utes.mongo.certClient.crud');
var newclient = new Clients ({
    commonName:String,
    countryName:String,
    ST:String,
    localityName:String,
    organizationName:String,
    OU:String,
    keySize:String,
    passphrase:String,
    p12FileName:String
});

	function connMongo(req, res) {
		// Connection URL
		  const url = 'mongodb://127.0.0.1:27017/cert_clients\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
		  usrDb.getMongoClient(url);		
	};

	/*function getSamlAssert(uid, req, res, next) {
		// db fetch start
		connMongo(req, res);
		usrDb.getUserStruct(uid, req, res, next).then(res => {
			if (uid != null && uid != '') {
				var data = JSON.stringify(usrStruct);
				JSON.parse(data, (key, value) => {
					  if (typeof value === 'string') {
					    //console.log("key:  " + key);
					    if(key === 'nameIdentifier') newuser.nameIdentifier = value;
					    if(key === 'emailAddress') newuser.emailAddress = value;
					    if(key === 'fullname') newuser.fullname = value;
					    if(key === 'firstname') newuser.firstname = value;
					    if(key === 'lastname') newuser.lasttname = value;
					    if(key === 'password') newuser.password = value;
					    if(key === 'mobilePhone') newuser.mobilePhone = value;
					    if(key === 'groups') newuser.groups = value;
					  }
					  //return value;
					});
				console.log("Exported: " + JSON.stringify(newuser));
				// db fetch end
				crAssert.options.cert = fs.readFileSync('SamlAssertCert.pem');
				crAssert.options.key = fs.readFileSync('SamlAssertKey.pem');
				crAssert.options.issuer = 'idp.utes.com';
				crAssert.options.lifetimeInSeconds =  '10800';
				//crAssert.options.Conditions = 'https://utes.com/saml';
				crAssert.options.audiences = 'https://utes.com/saml';
				//crAssert.options.NotBefore = "2021-04-23T23:51:43.745Z";
				//crAssert.options.NotOnOrAfter = "2021-04-23T23:51:43.745Z";
				crAssert.options.recipient = 'https://utes.com/saml/recipient';
				crAssert.options.inResponseTo = 'https://utes.com/saml/inresponseto';
				crAssert.options.includeAttributeNameFormat = true;
				crAssert.options.emailAddress = 'ajeet.phadnis@gmail.com';
				crAssert.options.nameIdentifier = 'user09876';
				crAssert.options.sessionIndex = 'jskjflksjeouotui4548958';
				crAssert.options.authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
				crAssert.options.attributes = {
					//'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
					'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailAddress': 'ajeet.phadnis@gmail.com',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Ajeet Phadnis',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstName': 'Ajeet',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/lastName': 'Phadnis',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayName': 'Ajeet Phadnis',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilePhone': '+4740634044',
				    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': 'Admin'
				}

				
				//console.log("getSamlAssert001: " + crAssert.options.cert); 
				crAssert.createSamlAssert(crAssert.options, req, res, next);

			} else {
				console.log("  User does not exist");
			}}).catch(err => console.log(err)); 		
	}
exports.getSamlAssert = getSamlAssert;*/
