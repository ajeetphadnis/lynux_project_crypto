/**
 * http://usejsdoc.org/
 */
'use strict';

const controller = require('./com.utes.controller');

module.exports = function(app) {
	const bodyParser = require('body-parser');
	app.use(bodyParser.urlencoded({ extended: true }));
    //app.route('/execServ').get(controller.execServ);
    //app.route('/postServ').post(controller.postServ);
    app.route('/cert_chain').get(controller.cert_chain);
    app.route('/cert_chain').post(controller.cert_chain);
    app.route('/client_start').get(controller.client_start);
    app.route('/client_start').post(controller.client_start);
    app.route('/profile_client').get(controller.profile_client);
    app.route('/profile_client').post(controller.profile_client);
    app.route('/login_client').get(controller.login_client);
    app.route('/login_client').post(controller.login_client);
    app.route('/register_client').get(controller.register_client);
    app.route('/register_client').post(controller.register_client);
    app.route('/client_secureEnv').get(controller.client_secureEnv);
    app.route('/client_secureEnv').post(controller.client_secureEnv);
    app.route('/jwks').get(controller.jwks);
    app.route('/jwks').post(controller.jwks);
    //app.route('/jwt').get(controller.jwt);
    app.route('/ocsp').get(controller.ocsp);
    app.route('/ocsp').post(controller.ocsp);
   
};