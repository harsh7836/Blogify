const { createHmac, randomBytes } = require("crypto");
const { createTokenForUser } = require("../services/authentication");
const { Schema, model } = require("mongoose");

const userSchema = new Schema({
    fullName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    salt: {
        type: String,
        // required: true,
    },
    password: {
        type: String, 
        required: true,
    },
    profileImageURL: {
        type: String,
        default: "/images/default.jpeg",
    },
    role: {
        type: String,
        enum: ["USER", "ADMIN"],
        default: "USER",
    },
},  { timestamps: true});


userSchema.pre("save", function (next) {
    const user = this;

    if(!user.isModified("password")) return;

    const salt = randomBytes(16).toString("hex");
    const hashedPassword = createHmac("sha256", salt)
       .update(user.password)
       .digest("hex");// give me in a hex form 

    this.salt = salt;
    this.password = hashedPassword;

    next();
});


userSchema.static('matchPasswordAndGenerateToken', async function(email, password){
    const user = await  this.findOne({ email });
    if(!user) throw new Error('User not found!');

    const salt = user.salt;
    const hashedPassword = user.password;

    const userProvidedHash = createHmac("sha256", salt)
       .update(password)
       .digest("hex");

    if(hashedPassword !== userProvidedHash) throw new Error('Incorrect Password');

    // return { ...user._, password: undefined, salt: undefined };
    const token = createTokenForUser(user);
    return token;
});

const user = model("user", userSchema);

module.exports = user;