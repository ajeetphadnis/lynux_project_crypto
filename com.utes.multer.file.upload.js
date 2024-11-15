const path = require('path');
const fs =  require('fs');
const multer = require("multer");
const  upload = multer({ dest: "uploads/" });
const bodyParser= require('body-parser');

var fcontent;

https://code.tutsplus.com/tutorials/file-upload-with-multer-in-node--cms-32088
    // SET STORAGE
    var storage = multer.diskStorage({
      destination: function (req, file, cb) {
        cb(null, './uploads');
      },
      filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now());
      }
    })
    
    var mupload = multer({ storage: storage });


async  function getFileContent (file ) {
    var contnt;
 // res.send(file)
	fs.readFile(file['path'], function (err, data) {
		if (err) throw err;
	  // data will contain your file contents
	  console.log("getFileContent:  " + data);
	  fcontent = data;		
	  return  fcontent;		
	});
}
 
 
 async function wrapperFileContent(file) {
     fcontent = await getFileContent (file );
     console.log("wrapperFileContent:  " + fcontent);
     exports.fcontent;
     return fcontent;
 }

exports.wrapperFileContent = wrapperFileContent;
exports.getFileContent = getFileContent;
exports.fcontent = fcontent;