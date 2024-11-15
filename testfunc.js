// good link: https://www.bezkoder.com/node-js-express-file-upload/
// this example is based:
// https://afteracademy.com/blog/file-upload-with-multer-in-nodejs-and-express
const path = require('path');
const fs =  require('fs');
const multer = require("multer");
const  upload = multer({ dest: "uploads/" });
const express = require("express");
const bodyParser= require('body-parser');
var fileUtil = require('./com.utes.multer.file.upload');
const app = express();
app.use(express.json());
            
            // ROUTES WILL GO HERE
            app.get('/views', function(req, res) {
                // res.json({ message: 'WELCOME' });
            	res.sendFile(path.join(__dirname, '/views/index.html'));
            });
            
            
            
            app.post('/uploadfile', upload.single('myFile'), (req, res, next) => {
        	try {
                  const file = req.file
                  if (!file) {
                    const error = new Error('Please upload a file');
                    error.httpStatusCode = 400;
                    return next(error);
                  } else {
                      console.log("path:  " + file['path']);
                      var content = fileUtil.wrapperFileContent (file );
                      console.log("Server:Content1:   " +  JSON.stringify(content));
                      console.log("Server:Content2:   " +  fileUtil.fcontent);
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

            
            
            function uploadFiles(req, res) {
            	console.dir(req.body);
            	console.log(req.files);
            	res.json({ message: "Successfully uploaded files" });
            }
            
            app.listen(5000, () => {
            	console.log(`Server started...`);
            });
