/**
 * http://usejsdoc.org/
 */
'use strict';

var properties = require('../package.json')
var cert_chain = require('../service/com.utes.cert.chain');
var clientUtils = require('../models/com.utes.cert.clientUtils');
var jwksUtils = require('../jwks/com.utes.jwks.createJWKS');
var jwtUtils = require('../jwks/com.utes.jwks.jwe.createJWT');
var clntSecureEnv = require('../crypto_xml/com.utes.secure.env');


var controllers = {
	cert_chain: function(req, res) {
	cert_chain.cert_chain(req, res);
    },
    client_start: function(req, res) {
    	clientUtils.client_start(req, res);
    },
    profile_client: function(req, res) {
	clientUtils.profile_client(req, res);
    },
    login_client: function(req, res) {
    	clientUtils.login_client(req, res);
    },
    register_client: function(req, res) {
    	clientUtils.register_client(req, res);
    },
    client_secureEnv: function(req, res) {
    	clientUtils.client_secureEnv(req, res);
    },
    jwks: function(req, res) {
    	clientUtils.getJWKS(req, res);
    },
    jwt: function(req, res) {
    	jwtUtils.getJWT(req, res);
    },
    ocsp: function(req, res) {
	clientUtils.client_OCSPResponder(req, res);
    },
    
};

module.exports = controllers;
