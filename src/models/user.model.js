import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema({
    username : {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true,
    },

    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,        
    },

    password: {
        type: String,
        required: [true,'Passwod is required'],
    },
    
    refreshTokens: {
        type: String,
    },

    fullName: {
        type: String,
        required: true,
        trim: true, 
        index: true,
    },

    avatar: {
        type: String, //cloudinary url
        required: true,
    },

    coverImage: {
        type: String, //cloudinary url
    },
    
    watchHistory:[
        {
            type: Schema.Types.ObjectId,
            ref: "Video",

        }
    ],
    

},{timestamps: true})


userSchema.pre("save",async function(next) {
    if(!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password,10)
    next()
})

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password);
}

export const User = mongoose.model("User",userSchema)


userSchema.methods.generateAccessToken = function(){
    jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN.EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN.EXPIRY
        }
    )
}


//Jwt is a bearer token strong security is used as an requisite to acces the required data