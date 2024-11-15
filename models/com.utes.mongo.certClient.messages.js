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

const mongoose =  require("mongoose");
passportLocalMongoose =  require("passport-local-mongoose"); 
const messageSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
    },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true },
);

messageSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model('Message', messageSchema);
