/**
 * http://usejsdoc.org/ This login app is based on :
 * https://codebun.com/login-registration-nodejsexpress-mongodb/
 */
global.clientdata;
require('dotenv').config();
const express               =  require('express'),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose");
	  fs					=  require("fs");
	  const path = require('path');
	  const multer = require('multer');
	  const upload = multer({dest:'./uploads'});
	  
      const Clients         =  require("./com.utes.cert.clients");
      var clientDb = require('./com.utes.mongo.certClient.crud');
      var clientdt = require('./com.utes.mongo.certClient.crud');
      var clientCert = require('../rsa_domain/com.utes.cert.clientDomain_certCreate');
      var clntSecEnv = require('../crypto_xml/com.utes.secure.env');
      var ocsp = require('../rsa_domain/com.utes.verify.p12.verifyClientCerts');
      var jwksUtils = require('../jwks/com.utes.jwks.createJWKS');
      var pemJWKS = require('../jwks/com.utes.pem-to-jwks');
      // var usr = require('./com.utes.mongo.crud').usr; ;
      // const MongoClient = require('mongodb').MongoClient;
      const assert = require('assert');
      const models = { Clients};
      var client;
      var db;
   // a variable to save a session
      var session;
      passport.use(new LocalStrategy({
	    usernameField: 'clientId',
	    usernameQueryFields: ['clientId']
	  }, Clients.authenticate()));
      

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
  
  ksVals = {
			CustomerId: '',
			Timestamp: '',
			xks: '',
			stdks: '',
	};

 	
  /**
   * 
   * 
   * 
   * 
   * @param firstname
   * @returns
   * 
   */
	function connMongo(req, res) {
		// Connection URL
	    // console.log("ENV: " + JSON.stringify(process.env));
	    var conStr = process.env.DATABASE;
	    console.log("ENV:   " + conStr);
    	  const url = conStr+'{ useNewUrlParser: true, useUnifiedTopology: true}';
    	  clientDb.getMongoClient(url);		
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function client_start(req, res, next) {
		// mongoose.connect("mongodb://localhost:27017/auth_users");
		req.app.use(require("express-session")({
			secret:"userPW123456",// decode or encode session
			    resave: false,          
			    saveUninitialized:false    
		}));
		passport.serializeUser(Clients.serializeUser());       // session
									// encoding
		passport.deserializeUser(Clients.deserializeUser());   // session
									// decoding
		passport.use(new LocalStrategy(Clients.authenticate()));
		req.app.set("view engine","ejs");
		req.app.use(bodyParser.urlencoded({ extended:true }));
		req.app.use(passport.initialize());
		req.app.use(passport.session());		
		res.render('client_start');
	};
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function getP12FileName(dir, strtStr, endStr) {
		// const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr) && file.endsWith(endStr)) {
				// console.log(file);
				return file;
			}	  
		}
	};
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function getUploadFileName(dir, strtStr, endStr) {
		// const dir = '/Users/flavio/folder'
		const files = fs.readdirSync(dir);
		
		for (const file of files) {
			if (file.startsWith(strtStr)) {
				console.log(file);
				return file;
			}	  
		}
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function getUploadFile(req, res, filn) {
		try {
			if(!filn) {
		    	console.log("getUploadFile: File could not be uploaded ...." );
		    } else {
		    	// console.log("Content File path: " +
			// JSON.stringify(req.files.target_file.tempFilePath));
		    	// var fpath = JSON.stringify(filn.tempFilePath);
		    	// var fName = getUploadFileName('./uploads', 'tmp',
			// '');
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

	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function profile_client(req, res, next) {
		res.render('profile_client');
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function login_client(req, res, next) {
		var exists = false;
		var resp = res;
		if (req.method === 'GET' && req.method !== 'POST') {
			console.log("login_client: " + req.method);
			res.render('../views/client_login');
			// res.sendFile('login_user.html');
		  }
		if (req.method === 'POST' && req.method !== 'GET') {
			console.log("login_client: " + req.method);
			connMongo(req, res);
// // configure passport
// var LocalStrategy = require("passport-local").Strategy;
// passport.use(new LocalStrategy({
// usernameField: 'clientId',
// usernameQueryFields: ['clientId']
// }, passport.authenticate()));
			passport.authenticate("local", {
			    	successRedirect: "../views/clientCreateCertFromData",
			    	failureRedirect: "../views/login"
			    }), function (req, res) {
			    };

			// return await
			clientDb.getClient(req.body.clientId, req.body.clientPw, req, res, next).then(res => {
				// if (req != null && req != '' &&
				// req.body.password ===
				// global.usrdata.password) {
				if (req != null && req != '') {
				    client = req.body.clientId;
				    // req.app.connectEnsureLogin.ensureLoggedIn();
				    req.app.session = req.session;
				    req.app.session.clientId = req.body.clientId;
				    req.app.session.clientPw = req.body.clientPw;
				    console.log("Login Session1: " + req.app.session.clientId);
				    console.log("Login Session2: " + req.sessionID);
				    console.log("Login Session3: " + req.session.cookie.maxAge);
				    var data = JSON.stringify(clientdt);
				    console.log("Exported: " + data);
				    JSON.parse(data, (key, value) => {
					if (typeof value === 'string') {JSON.parse(data, (key, value) => {
					    if (typeof value === 'string') {
						if(key === 'passphrase') req.app.session.passphrase = value;
					    }
					});
					}});
					// console.log("password: " +
					// global.usrdata.password);
					exists = true;
					newclient.clientId = req.body.clientId;
				    	clientCert.createP12RSA_CLIENT_DOMAIN_TRUST_Cert(clientdt, '', req, res, next);
					// newclient.newclient = clientdt;
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
		// }
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
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
// clientDb.createClient(newclient, req, res, next);
// res.render("../views/client_login",
// {
// Clients: newclient
// }
			Clients.register(new Clients({clientId: req.body.clientId,commonName:req.body.commonName,countryName: req.body.countryName,
			    ST: req.body.ST,localityName: req.body.localityName,organizationName: req.body.organizationName,
			    OU: req.body.OU,keySize: req.body.keySize,passphrase: req.body.passphrase,p12FileName: req.body.p12FileName
			    }),req.body.clientPw,function(err,user){
			        if(err){
			            console.log(err);
			            res.render("../views/register");
			        }
			    console.log("Redirecting to login");
			    passport.authenticate("local", function(err, user, info) {

				    if (err) return next(err); 
				    if (!user) return res.render('../views/client_login'); 

				    req.logIn(user, function(err) {
				        if (err)  return next(err); 
				        return res.redirect("../views/client_start");
				    });

				})(req, res, next);
			});
		}
	};
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function client_secureEnv(req, res, next) {
		try {
			if (req.method === 'GET' && req.method !== 'POST') {
				res.render('../views/client_secureEnv');
			}
			if (req.method === 'POST' && req.method !== 'GET') {
			    console.log('ClientId:   ' +req.body.CustomerId+ "      :   " + req.body.TargetId + "     :   " + req.body.FileType );
			    req.app.session.clnt = req.body.CustomerId;
			    req.app.session.target = req.body.TargetId;
			    req.app.session.ftype = req.body.FileType
				console.log("Content File path001:  " + JSON.stringify(req.files));
				upload.single("Content")(req, res, (err) => {
				    if(err) {
				    	console.log("getUploadFile: File could not be uploaded ...." );
				    }
				 console.log("Mutler Middleware001:  " + JSON.stringify(req.files));
				var jstr = JSON.stringify(req.files);
			        var jsonVal = JSON.parse(jstr);
			        var jfpath =  jsonVal.Content.tempFilePath;
			        var fName = jsonVal.Content.name;
			        console.log("Mutler Middleware002: Present:  " + __dirname);
			        console.log("Mutler Middleware003: Path:  " +  jfpath);
			    	//console.log("Mutler Middleware003:  Content File path:  " +jfpath);
			    	fs.readFile((jfpath), function (err, data) {
			    		  if (err) throw err;
			    		  // data will contain your file contents
			    		  console.log("Content File Data:  " + data);
			    		  newenvVals.Content = data;
			    		  // delete file
			    		  
			    		  
			    		  fs.unlink(jfpath, function (err) {
			    		    if (err) throw err;
			    		    console.log('successfully deleted ' +fName);
			        	  });
			        	  //return data;
			      //  });
				  //});
			    /*if (req.file) {
			    	console.log("Mutler Middleware003:  " + JSON.stringify(req.file));
			    	var jstr = JSON.stringify(req.file);
			        var jsonVal = JSON.parse(jstr);
			        var jfpath = jsonVal["path"];
			    	console.log("Content File path:  " +jfpath);
			    	fs.readFile(jfpath, function (err, data) {
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
			   }*/
				console.log('ClientId:   ' +req.body.CustomerId+ "      :   " + req.body.TargetId + "     :   " + req.body.FileType );
			    //newenvVals.CustomerId = req.body.CustomerId;
			    newenvVals.CustomerId =  req.app.session.clnt;
			   //  req.app.session.target = req.body.TargetId;
				newenvVals.TargetId = req.app.session.target;
				var fname = getP12FileName('./rsa_domain/', req.app.session.clientId, 'p12');
				clntSecEnv.readP12PrvKey(newenvVals, req.app.session.clientId, './rsa_domain/'+fname, req.app.session.passphrase, './crypto_xml/nordea_EnvelopeTemplate.xml')
				var signedXml = fs.readFileSync("./crypto_xml/ApplicationRequest.xml").toString();
				console.log("client_secureEnv:  newenvVals: " + newenvVals);
				newenvVals.signedXml = signedXml.toString();
				res.render('../views/client_secureEnv',
						{
							newenvVals
						}
				);
			        });
			  });
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
				newenvVals.signedXml = 'Could not find user and its certificate in our repository - try to login with legitimate user id or certificate expired !!';
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
	
	
	 async function getJWKS(req, res, next) {
		 try {
				if (req.method === 'GET' && req.method !== 'POST' && req.app.session.clientId) {
				    console.log("getJWKS:Get:  " );				    
					//req.app.session = req.session;
					res.render('../views/client_jwks',
							{
							    ksVals
							});
				} 
				/*else {
					res.send('user not logged in !! ');
				}*/
				if (req.method === 'POST' && req.method !== 'GET') {
					 ksVals.CustomerId =  req.app.session.clientId;
					 uid = req.app.session.clientId;
					 console.log("getJWKS:POST:  " + uid);
					 pemJWKS.pem2jwks (uid, './rsa_domain/', req.app.session.clientPw, '','','');
					 await jwksUtils.createstdJWKStore(uid, './rsa_domain/', req.app.session.clientPw);
			 		 await jwksUtils.x5jwtsjson(uid,'./rsa_domain/', req.app.session.clientPw);
				 	//ksVals.CustomerId =  req.app.session.clnt;
			 		var xks = fs.readFileSync('./JWKSets/'+uid+'_x5cjwks.json').toString();
			 		var stdks = fs.readFileSync('./JWKSets/'+uid+'_stdjwks.json').toString();
			 		ksVals.stdks = stdks;
			 		ksVals.xks = xks;

			 		res.render('../views/client_jwks',
							{
							    ksVals
							});
				}
			} catch (err) {
				console.log(err);
			}
		}
	
	
	
	
	function clientClose() {
		client.close();
	};


	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	function clientClose() {
		client.close();
	};



// exports.connectMongo = connectMongo;
exports.connMongo = connMongo;
exports.client = client;
exports.db = db;
exports.client_start = client_start;
exports.profile_client = profile_client;
exports.login_client = login_client;
exports.register_client = register_client;
exports.client_secureEnv = client_secureEnv;
exports.client_OCSPResponder = client_OCSPResponder;
exports.getJWKS = getJWKS;

connMongo('','');