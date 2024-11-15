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
global.clientdata;
var clientdt;
var clientStruct;
const {MongoClient} = require('mongodb'),
	  bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose");
const dotenv = require("dotenv")
dotenv.config({ path: "../.env/"})

var Client = require('./com.utes.cert.clients');
var Message = require('./com.utes.mongo.certClient.messages');
var dbClient;

console.log('mongo database 001:  ');


	  var client4 = new Client ({
	      clientId: '',
	      clientPw: '',
	      commonName: '',
	      countryName: '',
	      ST: '',
	      localityName: '',
	      organizationName: '',
	      OU: '',
	      keySize: '',
	      passphrase: '',
	      p12FileName: ''
	  });
	  

	  
	  /**
	   * 
	   * 
	   * 
	   * 
	   * @param firstname
	   * @returns
	   * 
	   */
	async function listDatabases(client){
	    databasesList = await client.db().admin().listDatabases();
	    console.log('mongo database 004:  ');
	    console.log("Databases:");
	    databasesList.databases.forEach(db => console.log(` - ${db.name}`));
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
	async function getMongoClient(uri) {
		/**
		   * Connection URI. Update <username>, <password>, and <your-cluster-url> to reflect your cluster.
		   * See https://docs.mongodb.com/ecosystem/drivers/node/ for more details
		   */
		  //const uri = "mongodb://Administrator:Ajeet78654321@localhost:27017/test?authSource=Administrator&retryWrites=true&w=majority&ssl=false";
		  client = new MongoClient(uri, { useUnifiedTopology: true , useNewUrlParser: true });
		  await client.connect();
		  dbClient = client;
		  return client;		
	}
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function createClient(Client, req, res, next) {
		const myDb = client.db('cert_clients');
		const myTab = myDb.collection('clients');
		const result = await myTab.insertOne(Client);
		console.log(
			      `${result.insertedCount} documents were inserted with the _id: ${result.insertedId}`,
			    );
	}
	
	async function getClient(clientid, req, res, next) {
		console.log("getClient001:   called ....");
		const myDb = client.db('cert_clients');
		const myTab = myDb.collection('clients');
		// Query for a user that has nameIdentifier field value in userid
	    const query = { clientId: clientid };
	    console.log("getClient002:  " + clientid);
	    const options = {
	    	      // sort matched documents in descending order by rating
	    	      sort: { rating: -1 },
	    	      // Include only the `title` and `imdb` fields in the returned document
	    	      projection: { clientId: 1 , clientPw: 1 , commonName: 1, countryName: 1, ST: 1, localityName: 1, organizationName: 1, OU: 1, keySize: 1, passphrase: 1, p12FileName: 1},
	    	    };
	    console.log("getClient003:  called ....");
	    clientdt = await myTab.findOne(query, options);
	    if (clientdt == null) {
		clientdt = {};
	    }
	    exports.clientdt = clientdt;
	    //global.usrdata = usrdt;
	    //console.log("getUser004:  " + JSON.stringify(global.usrdata));
	    console.log(clientdt );
	    return clientdt;
	}
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function getClientStruct(clientid, req, res, next) {
		console.log("getClientStruct001:   called ...." + clientid);
		const myDb = client.db('cert_clients');
		const myTab = myDb.collection('clients');
		// Query for a user that has nameIdentifier field value in userid
	    const query = { clientId: clientid };
	    console.log("getClientStruct002:  " + clientid);
	    console.log("getClientStruct003:  called ....");
	    clientStruct = await myTab.findOne(query);
	    if (clientStruct == null) {
		console.log("getClientStruct004:  clientStruct is null !!");
		clientStruct = {};
	    }
	    exports.clientStruct = clientStruct;
	    global.clientdata = clientStruct;
	    console.log("getUserStruct005:  " + JSON.stringify(clientStruct));
	    console.log(clientStruct );
	    return clientStruct;
	}

	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function deleteClient(clientid, req, res, next) {
		const myDb = client.db('cert_clients');
		const myTab = myDb.collection('clients');
		// Query for a user that has nameIdentifier field value in userid
	    const query = { clientId: clientid };
	    await myTab.deleteOne(query).then((result) => {
	        console.log('client deleted');
	        console.log(result);
	    }).catch((err) => {
	        console.log(err);
	    }).finally(() => {
	        //client.close();
	    });
	}
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function updateClient(clientid, updat, req, res, next) {
		const myDb = client.db('cert_clients');
		const myTab = myDb.collection('clients');
		// Query for a user that has nameIdentifier field value in userid
		// const updat = { $set: { fieldname: fieldvalue } };
	    const query = { clientId: clientid };
	    await myTab.updateOne(query, updat ).then((result) => {
	        console.log('client updated');
	        console.log(result);
	    }).catch((err) => {
	        console.log(err);
	    }).finally(() => {
	        //client.close();
	    });
	}
	
	
	
	/**
	 * 
	 * 
	 * 
	 * 
	 * @param firstname
	 * @returns
	 * 
	 */
	async function createListing(client, newListing){
	    const result = await client.db("sample_airbnb").collection("listingsAndReviews").insertOne(newListing);
	    console.log(`New listing created with the following id: ${result.insertedId}`);
	}
	
module.exports.listDatabases = listDatabases;
module.exports.getMongoClient = getMongoClient;
module.exports.createClient = createClient;
module.exports.getClient = getClient;
module.exports.deleteClient = deleteClient;
module.exports.updateClient = updateClient;
//module.exports.getClientdt = getClientdt;
//module.exports.setClientdt = setClientdt;
module.exports.dbClient = dbClient;
module.exports.clientdt = clientdt;
module.exports.clientStruct = clientStruct;
module.exports.getClientStruct = getClientStruct;