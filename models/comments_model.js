const mongoose=require('mongoose')
const Schema=mongoose.Schema
const User=require('./user_model')





const CommentsSchema=new Schema({
   text:String,
  date:{
   type:Date,
   default: Date.now
  },
   bookUser:{
      type:Schema.Types.ObjectId,
      ref:'User'
  }


})
//model name:Comment
module.exports=mongoose.model('Comment', CommentsSchema)