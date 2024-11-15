/**
 * http://usejsdoc.org/
 */
//Uploader.js
const path = require('path');
const util = require("util");
const crypto = require("crypto");
const multer = require('multer');

class Uploader {

    constructor() {
	console.log("Uploader_Constructor:  ")
        const storageOptions = multer.diskStorage({
            destination: function(req, file, cb) {
                cb(null, __dirname + '/uploads/')
            },
            filename: function(req, file, cb) {
                crypto.pseudoRandomBytes(16, function(err, raw) {
                    cb(null, raw.toString('hex') + Date.now() + '.' + file.originalname);
                });
            }
        });

        this.upload = multer({ storage: storageOptions });
    }

    async startUpload(req, res) {
        let filename;
        console.log("startUpload001:  "); // +   req.files[0].filename);
        try {
            const upload = util.promisify(this.upload.any());

            await upload(req, res);

           // filename = req.files[0].filename;
            const file = req.file;
            console.log("startUpload002:  " +JSON.stringify( file));
        } catch (e) {
            //Handle your exception here
            console.log("startUploadException:  " + e);
        }
       // res. setHeader('Content-Type', 'application/json');
        return  filename;
    }
}

exports.Uploader = Uploader;