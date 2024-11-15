/**
 * http://usejsdoc.org/
 */
const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express');
const fileUpload =  require('express-fileupload');
const busboy =  require("connect-busboy");
const bodyParser = require('body-parser'); // parser middleware
const session = require('express-session');  // session middleware
const passport = require('passport');  // authentication
const connectEnsureLogin = require('connect-ensure-login');// authorization
const cookieParser = require("cookie-parser");
const path = require('path');
const mongoose = require("mongoose");
const mongostore = require("connect-mongo");
LocalStrategy = require("passport-local").Strategy,
passportLocalMongoose =	require("passport-local-mongoose"),
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
mongoose.set('useUnifiedTopology', true);
usrdata = '';
var mongo = require('./models/com.utes.cert.clientUtils');
const Clients = require('./models/com.utes.cert.clients');


//import models, { mongo.connMongo } from './models';
mongoose.connect('mongodb://localhost:27017/cert_clients', { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
	var privateKey =  fs.readFileSync('nodeSrvPrvKey.pem');
	var certificate = fs.readFileSync('nodeSrvCert.pem');
	var credentials = {key: privateKey, cert: certificate};
	app = express();
	const port = process.env.PORT || 30005;
	//app.use(busboy());
	app.use(bodyParser.urlencoded({ extended: true }));
	// creating 1 hour from milliseconds
	const oneHr = 1000 * 60 * 60 ;
	//session middleware
	const MongoStore = mongostore(session);
	app.use(session({
	    secret: "786Phadnis7654321",
	    saveUninitialized:true,
	    cookie: { maxAge: oneHr },
	    resave: false,
	    store: new MongoStore({
	          mongooseConnection: mongoose.connection,
	          ttl: 14 * 24 * 60 * 60 // save session for 14 days
	        })
	}));
	app.use(passport.initialize());
	app.use(passport.session());
	
	// cookie parser middleware
	app.use(cookieParser());
	const routes = require('./api/com.utes.routes');
	// Set your static folder before any request handlers.
	app.use(express.static(__dirname+ '/public'));
	app.use(fileUpload({
	    useTempFiles : true,
	    tempFileDir : path.join(__dirname,'uploads'),
	}));

	//app.use(express.static("public"));
	app.set('views', __dirname + '/views'); // set express to look in this folder to render our view
	app.set('view engine', 'ejs'); // configure template engine
	//app.use(bodyParser.urlencoded({ extended: true }));
	//parse application/vnd.api+json as json
	app.use(bodyParser.json({ type: 'application/vnd.api+json' }));	
	console.log("Dir: " + __dirname);
	routes(app);
	https.createServer(credentials,app).listen(port);
	http.createServer(app).listen(30081);
});
