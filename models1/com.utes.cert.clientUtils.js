/**
 * http://usejsdoc.org/
 * This login app is based on : https://codebun.com/login-registration-nodejsexpress-mongodb/
 */
global.clientdata;
const express               =  require('express'),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose");
	  fs					=  require("fs");
	  const path = require('path');
      const Clients         =  require("./com.utes.cert.clients");
      var clientDb = require('./com.utes.mongo.certClient.crud');
      var clientdt = require('./com.utes.mongo.certClient.crud');
      var clientCert = require('../rsa_domain/com.utes.cert.clientDomain_certCreate');
      var clntSecEnv = require('../crypto_xml/com.utes.secure.env');
      var ocsp = require('../rsa_domain/com.utes.verify.p12.verifyClientCerts');
      //var usr = require('./com.utes.mongo.crud').usr; ;
      //const MongoClient = require('mongodb').MongoClient;
      const assert = require('assert');
      const models = { Clients};
      var client;
      var db;
   // a variable to save a session
      var session;
      

      var newclient = new Clients ({
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
	});
      
  newenvVals = {
			CustomerId: '',
			Timestamp: '',
			TargetId: '',
			Content: '',
			keyInfo: '',
			signedXml: '',
  };

 	
	function connMongo(req, res) {
		// Connection URL
    	  const url = 'mongodb://localhost:27017/cert_clients\', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}';
    	  clientDb.getMongoClient(url);		
	};
	
	function client_start(req, res, next) {
		//mongoose.connect("mongodb://localhost:27017/auth_users");
		req.app.use(require("express-session")({
			secret:"userPW123456",//decode or encode session
			    resave: false,          
			    saveUninitialized:false    
		}));
		//passport.serializeUser(Clients.serializeUser());       //session encoding
		//passport.deserializeUser(Clients.deserializeUser());   //session decoding
		//passport.use(new LocalStrategy(Clients.authenticate()));
		req.app.set("view engine","ejs");
		req.app.use(bodyParser.urlencoded(
		      { extended:true }
		))
		req.app.use(passport.initialize());
		req.app.use(passport.session());		
		res.render('client_start');
	};
	
	
	function getP12FileName(dir, strtStr, endStr) {
		//const dir = '/Users/flavio/folder'
		console.log("getP12FileName:   dir:   " + dir + "  strtStr  " + strtStr +  "   endStr;   " + endStr);
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr) && file.endsWith(endStr)) {
				//console.log(file);
				return file;
			}	  
		}
	};
	
	
	function getUploadFileName(dir, strtStr, endStr) {
		//const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr)) {
				console.log(file);
				return file;
			}	  
		}
	};
	
	function getUploadFile(req, res, filn) {
		try {
			if(!filn) {
		    	console.log("getUploadFile: File could not be uploaded ...." );
		    } else {
		    	//console.log("Content File path:  " + JSON.stringify(req.files.target_file.tempFilePath));
		    	//var fpath = JSON.stringify(filn.tempFilePath);
		    	//var fName = getUploadFileName('./uploads', 'tmp', '');
		    	console.log("Content File path:  " + filn);
		    	fs.readFile('./uploads/'+filn, function (err, data) {
		    		if (err) throw err;
		    		  // data will contain your file contents
		    		  console.log("Content File Data:  " + data);
		
		    		// delete file
		    		fs.unlink('uploads/'+filn, function (err) {
		    		if (err) throw err;
		    		   console.log('successfully deleted ' + req.files.path);
		    		});
		        	return data;
		    });
		 }
	    } catch (err) {
	        res.status(500).send(err);
	    }
	};

	
	function profile_client(req, res, next) {
		res.render('profile_client');
	};
	
	async function login_client(req, res, next) {
		var exists = false;
		var resp = res;
		if (req.method === 'GET' && req.method !== 'POST') {
			console.log("login_client: " + req.method);
			res.render('../views/client_login');
			//res.sendFile('login_user.html');
		  }
		if (req.method === 'POST' && req.method !== 'GET') {
			console.log("login_client: " + req.method);
			connMongo(req, res);
			// return await 
			clientDb.getClient(req.body.clientId, req.body.clientPw, req, res, next).then(res => {
				//if (req != null && req != '' && req.body.password === global.usrdata.password) {
				if (req != null && req != '') {
				    client = req.body.clientId;
				    //req.app.connectEnsureLogin.ensureLoggedIn();
				    req.app.session = req.session;
				    req.app.session.clientId = req.body.clientId;
				    req.app.session.clientPw = req.body.clientPw;
				    console.log("Login Session1: " + req.app.session.clientId);
				    console.log("Login Session2: " + req.sessionID);
				    console.log("Login Session3: " + req.session.cookie.maxAge);
					console.log("Exported: " + JSON.stringify(clientdt));
					//console.log("password:  " + global.usrdata.password);
					exists = true;
					newclient.clientId = req.body.clientId;
				    	clientCert.createP12RSA_CLIENT_DOMAIN_TRUST_Cert(clientdt, '', req, res, next);
					//newclient.newclient = clientdt;
					resp.render("../views/clientCreateCertFromData",
			                {
			                    Clients: newclient
			                }
			        );

				} else {
					console.log("Login failed ! User does not exist");
					exists = false;
					resp.render("../views/register_client",
			                {
			                    Clients: newclient
			                }
			        );
				}}).catch(err => console.log(err)); 
		}
		//}
	};
	
	function register_client(req, res, next) {
		if (req.method === 'GET' && req.method !== 'POST') {
			res.render('../views/register_client');
		}
		if (req.method === 'POST' && req.method !== 'GET') {
			newclient.clientId = req.body.clientId;
			newclient.clientPw = req.body.clientPw;
			newclient.commonName = req.body.commonName;
			newclient.countryName = req.body.countryName;
			newclient.ST = req.body.ST;
			newclient.localityName = req.body.localityName;
			newclient.organizationName = req.body.organizationName;
			newclient.OU = req.body.OU;
			newclient.keySize = req.body.keySize;
			newclient.passphrase = req.body.passphrase;
			newclient.p12FileName = req.body.p12FileName;

			connMongo(req, res);
			clientDb.createClient(newclient, req, res, next);
			res.render("../views/client_login",
	                {
	                    Clients: newclient
	                }
	        );
		}
	};
	
	function client_secureEnv(req, res, next) {
		try {
			if (req.method === 'GET' && req.method !== 'POST') {
				res.render('../views/client_secureEnv');
			}
			if (req.method === 'POST' && req.method !== 'GET') {
			    if(!req.files) {
			    	console.log("getUploadFile: File could not be uploaded ...." );
			    } else {
			    	//console.log("Content File path:  " + JSON.stringify(req.files.target_file.tempFilePath));
			    	var fpath = JSON.stringify(req.files.Content.tempFilePath);
			    	var fName = getUploadFileName('./uploads', 'tmp', '');
			    	console.log("Content File path:  " + fpath);
			    	fs.readFile('uploads/'+fName, function (err, data) {
			    		  if (err) throw err;
			    		  // data will contain your file contents
			    		  console.log("Content File Data:  " + data);
			    		  newenvVals.Content = data;
			    		  // delete file
			    		  fs.unlink('uploads/'+fName, function (err) {
			    		    if (err) throw err;
			    		    console.log('successfully deleted ' + req.files.path);
			        	  });
			        	  return data;
			        });
			   }
			    newenvVals.CustomerId = req.body.CustomerId;
				newenvVals.TargetId = req.body.TargetId;
				var fname = getP12FileName('./rsa_domain/', newenvVals.CustomerId, 'p12');
				clntSecEnv.readP12PrvKey(newenvVals, req.app.session.clientId, './rsa_domain/'+fname, req.app.session.clientPw, './crypto_xml/nordea_EnvelopeTemplate.xml')
				var signedXml = fs.readFileSync("./crypto_xml/ApplicationRequest.xml").toString();
				//console.log("client_secureEnv:  " + signedXml);
				newenvVals.signedXml = signedXml.toString();
				res.render('../views/client_secureEnv',
						{
							newenvVals
						}
				);
			}
		} catch (err) {
			console.log(err);
		}
	}
	
	
	function client_OCSPResponder(req, res, next) {
		try {
			if (req.method === 'GET' && req.method !== 'POST') {
			    console.log("client_OCSPResponder:Get:  " + req.query.userid + " cert_snr:   " + req.query.cert_snr);
			    if (req.query.userid && req.query.cert_snr) {
        			    // Access the provided 'page' and 'limt' query parameters
				req.app.session = req.session;
				req.app.session.userid = req.query.userid;
				req.app.session.cert_snr = req.query.cert_snr;
				console.log("client_OCSPResponder_GET:   " +  req.app.session.userid + "    " + req.app.session.cert_snr);
       				res.render('../views/client_cert_ocsp');
			    } else {
				res.send('userid or certificate serial nr. not provided');
			    }
			}
			if (req.method === 'POST' && req.method !== 'GET') {
			    console.log("client_OCSPResponder_POST: " );
			    console.log("client_OCSPResponder_POST: " +  req.app.session.userid + "    " + req.app.session.cert_snr);
			    if(req.app.session.userid && req.app.session.cert_snr) {
			    	console.log("client_OCSPResponder001: " +  req.app.session.userid + "    " + req.app.session.cert_snr);
			    	var fname = getP12FileName('./rsa_domain/', req.app.session.userid, 'p12');
			    	console.log("client_OCSPResponder002: " +  fname);
			    	var data = ocsp.getP12Certs(req.app.session.userid, './rsa_domain/'+fname, req.app.session.userid);
			    	newenvVals.signedXml = data;
				res.render('../views/client_cert_ocsp',
					{
					    newenvVals
					});
			    } else {
				newenvVals.signedXml = 'Could not file user and its certificate in our repository - try to login with legitimate user id';
				res.render('../views/client_cert_ocsp',
					{
					    newenvVals
					});
			   }
			}
		} catch (err) {
			console.log(err);
		}
	}
	
	function clientClose() {
		client.close();
	};



//exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.client = client;
exports.db = db;
exports.client_start = client_start;
exports.profile_client = profile_client;
exports.login_client = login_client;
exports.register_client = register_client;
exports.client_secureEnv = client_secureEnv;
exports.client_OCSPResponder = client_OCSPResponder;