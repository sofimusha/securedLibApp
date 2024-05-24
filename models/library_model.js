const mongoose=require('mongoose')
const Schema=mongoose.Schema
const Comment=require('./comments_model')
const User=require('./user_model')


const LibrarySchema=new Schema({
    title:String,
    author:String,
    ISBN:String,
    plot:String,
    link:String,
    // 
    category: {
        type: String,
        lowercase: true,
        enum: ['computer science', 'economics', 'physics', 'history', 'fiction', 'comedy','other']
    },
    image:[
        {
            url:String,
            filename:String
        }
    ],
    price:Number,
    comments:[{
        type:Schema.Types.ObjectId, ref:'Comment'
    }],
    bookUser:{
        type:Schema.Types.ObjectId ,
        ref:'User'
    },



})
//when deleting a book, also delete all comments related to it from comments collection in mongo
LibrarySchema.post('findOneAndDelete',async function(doc){
    if(doc){
        await Comment.deleteMany({
            _id:{
                $in:doc.comments
            }
        })
    }
})


module.exports=mongoose.model('Book', LibrarySchema)