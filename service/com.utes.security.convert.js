const xmlParser 		  = require('xml2js'),
parseString 		  	  = require('xml2js').parseString,
//stripPrefix 			  = require('xml2js').processors.stripPrefix;
fs 						  = require('fs'),
JWT 				  	  = require('jsonwebtoken'),
xmlParser1 				  = require('xml2json'),
formatXml 				  = require('xml-formatter'),
bodyParser 				  = require('body-parser');
//var jwtVerify = require('../api/com.utes.jwt_sign_verify');
var stripPrefix = require('xml2js').processors.stripPrefix;
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
const path = require('path');
var secureRandom = require('secure-random');
global.pubstr;
const jwtks2pem = require('./com.utes.jwtks-to-pem');
//const jwt2cert = require('../api/com.utes.jwt.cert');
const pem2jwks  = require('./com.utes.pem-to-jwks');
//const saml2json = require('./com.utes.saml-to-json');
const idpsaml2jwt = require('./com.utes.idp.saml2jwt');
const jwt2Idpsaml = require('./com.utes.idp.jwt2saml');
const selfsignedCert = require('../api/com.utes.security.createUserSelfSignedCert');
const Users =  require("../models/com.utes.auth.users");
const assert = require('./com.utes.saml.user_initiated');
const dashRE = /-/g;
const lodashRE = /_/g;


var newuser = new Users ({
	  nameIdentifier: '',
	  emailAddress: '',
	  fullname: '',
	  firstname: '',
	  lastname: '',
	  password: '',
	  mobilePhone: '',
	  groups: '',
});

var user = {
  uid: '',
  serv: '',
  samlassrt: '',
  jwtoken: '',
  x509token: '',
  newuser: {}
};

function convrt (req, res, next) {
		req.app.set("../views", path.join(__dirname));
		req.app.set("view engine", "ejs");
		const { check, validationResult } = require('express-validator');
		// call and create SAML Assert
		assert.getSamlAssert(req.body.uid, req, res, next);
		// SAML Assert
		//create application/x-www-form-urlencoded parser
		var urlencodedParser = bodyParser.urlencoded({ extended: true });
		var filjwt = './samlIdpResp2jwt_rsa_signed.jwt';
		var filsaml = './signedAssert.xml';
		var filpem = './phadnisinc.pem';
		res.render("../views/form_convrt",
                {
                    user: user
                }
            );
		user.uid = req.body.uid;
		user.serv = req.body.serv;
		console.log("user id:  " + user.uid);
		var convrt = 'convrt';
		var undef;

		var signingKey = secureRandom(256, { type: 'Buffer' }); // Create a highly random byte array of 256 bytes
		console.log("uid  :  " + user.uid + "    user.serv: " + user.serv);
		//res.sendFile(path.join(__dirname,'../views/SampleForm.ejs'));
		if ( typeof user.uid !== undef && user.uid !== null && typeof user.serv !== undef && user.serv !== null) {			
			//Do Something
			var myHtmlData;
			var msg;
			var email1 = "ajeet.phadnis@dfo.no";
			var samlA;
			var x509Token;
			//console.log("jwtFileName:   " + filsaml);
			//var ret = jwt2Idpsaml.jwt2IdpSaml(fval, req, res, next);
			if (user.serv === 'serv1') {
				var ret = idpsaml2jwt.idpSaml2Jwt(user.uid, filsaml, req, res, next);
				user:uid = req.body.uid;
				res.render("../views/form_convrt",
		                {
		                    user: user
		                }
		            );
				fs.readFile(filsaml, (err, data) => {
				    if(err) {
				        throw err;
				    } else {
						//req.body.jwtoken = data;
						user.samlassrt = data;
						//console.log("PostService:  000:  " +  user.jwtoken);
			        } 
				});
				fs.readFile('./samlIdpResp2jwt_rsa_signed.jwt', (err, data) => {
				    if(err) {
				        throw err;
				    } else {
						//req.body.jwtoken = data;
						user.jwtoken = data;
						//console.log("PostService:  000:  " +  user.jwtoken);
			        } 
				});
				user.x509token = 'SAML Token => JW Token';
			}
			if (user.serv === 'serv2') {
				var ret = jwt2Idpsaml.jwt2IdpSaml(user.uid, filjwt, req, res, next);
				user.samlassrt = ret;
				user.jwtoken = global.jwstr;
				console.log("PostService:  000:  " +  user.jwtoken);
				fs.readFile('data.xml', 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						user.samlassrt = data;
					}
					
					});
				fs.readFile('./samlIdpResp2jwt_rsa_signed.jwt', 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						const base64Url = data.split('.')[1];						  
						if (base64Url === undefined) return null;
						const base64 = base64Url.replace(dashRE, '+').replace(lodashRE, '/');
						var jsonStr = Buffer.from(base64, 'base64').toString();
						//console.log("parseJwtCrPem002: " + jsonStr);
						user.jwtoken = jsonStr;
					}
					
					});
				user.x509token = 'JW Token => SAML Token';
			}
			if (user.serv === 'serv3') {
				var ret = jwtks2pem.jwtks2pem(user.uid, filjwt, req, res, next);
				user.samlassrt = 'JWToken => X509';
				fs.readFile('./samlIdpResp2jwt_rsa_signed.jwt', 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						const base64Url = data.split('.')[1];						  
						if (base64Url === undefined) return null;
						const base64 = base64Url.replace(dashRE, '+').replace(lodashRE, '/');
						var jsonStr = Buffer.from(base64, 'base64').toString();
						//console.log("parseJwtCrPem002: " + jsonStr);
						user.jwtoken = jsonStr;
					}
					
					});
				fs.readFile(user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						user.x509token = data;
					}
					
					});
			}
			if (user.serv === 'serv4') {
				//let rawdata = fs.readFileSync(fil);
				//let jstr1 = JSON.parse(rawdata);
				selfsignedCert.createUserSelfSignedCert(user.uid, '', req, res, next);
				filpem = './'+user.uid+'_selfsigned.crt';
				var jwt = pem2jwks.pem2jwks(user.uid, filpem, req, res, next);
				user.samlassrt = 'X509 Token => JW Token';
				fs.readFile("./pem2jwtks.json", 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						//console.log("Converter:004: " + data);
						user.jwtoken = data;
					}
					
					});
				fs.readFile('./'+user.uid+'_selfsigned.crt', 'utf8' , (err, data) => {				
					if (err) {
						console.error(err);
						return;
					} else {
						//console.log("Converter:004: " + data);
						user.x509token = data;
					}
					
					});
			}
			
		    // get saml data
//	    	fs.readFile( "./data.xml", function(err, data) {
//				if (err) {
//					console.log("error getting   " + jwtFileName + "    file");
//				} else {
//					parseString(data, function(err, result) {
//						//samlA = JSON.stringify(result);
//						user.samlassrt = JSON.stringify(result);
//						//samlA = data.toString();
//						//console.log("PostService:  001:  " + user.samlassrt);
//					});
//				}
//	    	});
//	    	fs.readFile( "./idp-public-cert.pem", 'utf8', function (err,response) {
//	    		if (err) {
//	    			console.log(err);
//	    		} else {
//			        user.x509token = response;
//			        //res.setHeader('Content-Type', 'text/plain');
//			        //res.send(JSON.stringify({response}));
//	    		}
//	    	});
        }
	}
exports.convrt = convrt;