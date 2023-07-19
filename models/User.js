const mongoose = require('mongoose');  //to create new user model
const { isEmail } = require('validator');  //importing from validator package to validate an email
const bcrypt = require('bcrypt');      // to hash password(make it secure)

const userSchema = new mongoose.Schema({    //schema define the structure of user document
    email: {
      type: String,
      required: [true, 'Please enter an email'],     //first value of array is value of key i.e if its required or not. second value is custom error 
      unique: true,    //no user can signup with the same email twice
      lowercase: true,
      validate: [isEmail, 'Please enter a valid email']   //to make sure user enters an email; isemail is basically from package we installed
    },
    password: {
      type: String,
      required: [true, 'Please enter a password'],
      minlength: [6, 'Minimum password length is 6 characters'],
    }
  });
  


  // fire a function after doc saved to db
  // userSchema.post('save', function (doc, next) {    //after the save event occurs then fire this function (when new doc is saved to database)
  //   console.log('new user was created & saved', doc);
  //   next();   //to go to the next middlewear. have to do that in any kind of mongoose middlewaer
  // });


  
  // fire a function before doc saved to db
  userSchema.pre('save', async function (next) {    //we can't use arrow function here bcs we are using this which refers to instance of user object
    // console.log('user about to be created & saved', this);   //local instance of the user before we save it to the db
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);  //first argument is password we want to hash, sec arg is salt
    next();
  });
  

  // static method to login user
userSchema.statics.login = async function(email, password) {
  // looking for in db the user with this email  
  const user = await this.findOne({ email });   //email:email //"this" refers to user model itself  matching the email user enterd with the email in db
  // if theres user then it will give the user otherwise it will give undefined
  if (user) {
    // comparing hashed password
    const auth = await bcrypt.compare(password, user.password);  //bcrypt is going to hash it and compare hashed passwords
    //                        not hashed password, hashed password from db
    if (auth) {   //if pasw has matched
      return user;
    }
    throw Error('incorrect password');
  }
  throw Error('incorrect email');
};

                    
  
//model based on this schema  
  const User = mongoose.model('user', userSchema); // argument(name, schema) ;name must be singular of whatever we define our database collection(users)
  
  module.exports = User;