//var date = new Date();
//console.log("xml Parser6:  " + date );
//date.setHours(date.getHours()-1);
//console.log("xml Parser6:  " + date.toISOString());
//var seconds = date.getTime() / 1000; // 1440516958
//nbSecs = seconds;
//seconds = seconds+36000;
//console.log("xml Parser6:  " + date + "       " + seconds);
//
//var sn = Math.floor(Math.random() * 900000);
//console.log("SN:  " + sn);
//var dt = new Date();
//mm = (dt.getMonth() + 1).toString().padStart(2, "0");
//dd   = dt.getDate().toString().padStart(2, "0");
//var sn =sn+'-'+mm+dd;
//console.log('snum:  ' + sn);


//const fs = require('fs');

//function getP12FileName(dir, strtStr, endStr) {
//	//const dir = '/Users/flavio/folder'
//	const files = fs.readdirSync(dir);
//	
//	for (const file of files) {
//		if (file.startsWith(strtStr) && file.endsWith(endStr)) {
//			//console.log(file);
//			return file;
//		}	  
//	}
//}

//function getUploadFile(req, res) {
//	try {
//        if(!req.files) {
////            res.send({
////                status: false,
////                message: 'No file uploaded'
////            });
//        	console.log("getUploadFile: File could not be uploaded ...." );
//        } else {
//        	fs.readFile(req.files.path, function (err, data) {
//        		  if (err) throw err;
//        		  // data will contain your file contents
//        		  console.log("Content File Data:  " + data);
////
////        		  // delete file
////        		  fs.unlink(req.files.path, function (err) {
////        		    if (err) throw err;
////        		    console.log('successfully deleted ' + req.files.path);
////        		  });
//        		  return data;
//        		});
//        }
//    } catch (err) {
//        res.status(500).send(err);
//    }
//};
//
//var ret = getP12FileName('E:\\App2\\App2\\workspaces\\PhadnisWorkspace\\com.utes.cert.crypto\\rsa_domain', 'Integration_grp', 'p12');
//console.log(ret);
/* Content File path:  {"target_file":{"name":"NAB5.8259433097._11.lis","data":{"type":"Buffer","data":[]},"size":1863,"encoding":"7bit","tempF
ilePath":"E:\\App2\\App2\\workspaces\\PhadnisWorkspace\\com.utes.auth.protocol.exchange\\uploads\\tmp-1-1625065734502","truncated":false,"mi
metype":"application/octet-stream","md5":"7f3cfa7d85e38b3978b20d96c05404ca"}}*/

const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const app = express();
const readF = require('./readUploadFile');
const crypto = require('crypto');

app.use(fileUpload({
    useTempFiles : true,
    tempFileDir : path.join(__dirname,'uploads'),
}));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'indexFile.html'));
});

app.post('/', (req, res) => {
    
    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }
    if(!req.files) {
    	console.log("getUploadFile: File could not be uploaded ...." );
    } else {
    	//console.log("Content File path:  " + JSON.stringify(req.files.target_file.tempFilePath));
    	var fpath = JSON.stringify(req.files.target_file.tempFilePath);
    	var fName = readF.getUploadFileName('./uploads', 'tmp', '');
    	console.log("Content File path:  " + fpath);
    	fs.readFile('uploads/'+fName, function (err, data) {
    		  if (err) throw err;
    		  // data will contain your file contents
    		  console.log("Content File Data:  " + data);

    		  // delete file
    		  fs.unlink('uploads/'+fName, function (err) {
    		    if (err) throw err;
    		    console.log('successfully deleted ' + req.files.path);
        		  });
        		  return data;
        		});
   }
});


function getRandomHex(length) {
	    const genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
	    var hx = genRanHex(length);
	    hx = hx.replace(/..\B/g, '$&:');
	    return hx;
}

function compareDates(date1, date2) {
    var g1 = new Date();
}

// app.listen(3000, () => console.log('Your app listening on port 3000'));

//var ran = getRandomHex(16);
console.log(ran);