/**
 * 
 * example link: https://stackoverflow.com/questions/45540560/node-js-multer-upload-with-promise
 *
 *  Module Name:	com.utes.cert.crypto//multerApp.js
 *  Created On:	31. jan. 2022
 *  Module Features: 
 */
 
//app.js
const path = require('path');
 const fs = require('fs');
 const multer = require("multer");
 const  upload = multer({ dest: "uploads/" });
 const express = require('express');
 const cors = require('cors');
 const bodyParser = require('body-parser');
 const app = express();

 app.use(cors({credentials: true, origin: 'http://localhost:4200'}));
 app.use(bodyParser.json());
 app.use(bodyParser.urlencoded({ extended: true }));

 const Uploader = require('./Uploader.js').Uploader;
 const uploader = new Uploader();
 // ROUTES WILL GO HERE
 app.get('/views', function(req, res) {
     // res.json({ message: 'WELCOME' });
 	res.sendFile(path.join(__dirname, '/views/index.html'));
 });
 
 
 
 
 
 app.post('/uploadfile', upload.single('myFile'), (req, res, next) => {
	try {
	    res. setHeader('Content-Type', 'application/json');
       const file = req.file
       if (!file) {
         const error = new Error('Please upload a file');
         error.httpStatusCode = 400;
         return next(error);
       } else {
           console.log("path:  " + file['path']);
           var cont =   uploader.startUpload(req, res);
           console.log("Server:Content1:   " +  JSON.stringify(cont));
          // console.log("Server:Content2:   " +  fileUtil.fcontent);
        // delete file
   		fs.unlink(file['path'], function (err) {
   		if (err) throw err;
   		   console.log('successfully deleted ' + file.path);
		});
       }
     } catch (err) {
         res.status(500).send(err);
     }
 });
 
 app.listen(5000, () => {
 	console.log(`Server started...`);
 });