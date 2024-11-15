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
const selfsignedCert = require('../rsa_domain/com.utes.cert.clientDomain_certCreate');
const Clients =  require("../models/com.utes.cert.clients");
const assert = require('./com.utes.cert.client_initiated');
const dashRE = /-/g;
const lodashRE = /_/g;

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

function getClientData(req, res, next) {
    req.app.set("../views", path.join(__dirname));
    req.app.set("view engine", "ejs");
    const { check, validationResult } = require('express-validator');
    //create application/x-www-form-urlencoded parser
    var urlencodedParser = bodyParser.urlencoded({ extended: true });
    res.render("../views/form_convrt",
            {
                Clients: newclient
            }
        );
    console.log("Client Data:  " + res.body);
}
