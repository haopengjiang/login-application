var express = require('express');
var router =express.Router();

var passport =require('passport');
var LocalStrategy= require('passport-local').Strategy;
const jwt= require('jsonwebtoken');

var User =require('../models/user');

// Register
router.get('/register', function(req,res){
	res.render('register');

});

//Login

router.get('/login', function(req,res){
	res.render('login');

});


/* 
//create token

router.post('/login/posts/v1',(req,res)=>{
		//Mock Info
		const Customer={
			Customer_id: 1,
			Customer_name:'haopeng',
			Customer_email:'haopeng@gmai.com'

		}
		jwt.sign({Customer:Customer},'secretkey',(err,token)=>{
			res.json({
				token:token

			});
		});

});

*/
//verify token


router.post('/login/authenticate',verifyToken,(req,res)=>{
	jwt.verify(req.token, 'secretkey',(err, authData)=>{
		if(err){
			res.sendStatus(403);
		}else{
			res.json({
				message: 'Post created',
				authData
			});
		}

	});	
});



//Reigister user
router.post('/register', function(req,res){

	var name = req.body.name;
	var email =req.body.email;
	var username = req.body.username;
	var password =req.body.password;
	var password2 =req.body.password2;

	//Validation
	req.checkBody('name','Name is required').notEmpty();
	req.checkBody('email','Email is required').notEmpty();
	req.checkBody('email','Email is not valid').isEmail();
	req.checkBody('username','Username is required').notEmpty();
	req.checkBody('password','password is required').notEmpty();
	req.checkBody('password2','Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors: errors

		});
	}else{
		var newUser = new User({
			name: name,
			email: email,
			username: username,
			password:password
		});

		User.createUser(newUser,function(error,user){
				if(error) throw err;
				//console.log(user);

		});

		jwt.sign({newUser:newUser},'secretkey',(err,token)=>{
			if(err) throw err;
			console.log(token);
		});

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/users/login');
	}
});


passport.use(new LocalStrategy(
	function(username,password,done){
	    User.getUserByUsername(username,function(err,user){
			if(err) throw err;
			if(!user){
				return done(null,false,{message:'unknown User'});
			}
			User.comparePassword(password,user.password,function(err,isMatch){
				if(err) throw err;
				if(isMatch){
						return done(null,user);
				}else{
				return done(null,false,{message:'Invalid password'});
				}
			});

	  	});

	}));


passport.serializeUser(function(user,done){
	done(null,user.id);
});
passport.deserializeUser(function(id,done){
	User.getUserById(id,function(err,user){
		done(err,user);
	});

});


//Original login 
router.post('/login',
	passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login', failureFlash: true}),
	function(req,res){
		res.redirect('/');


	});






router.get('/logout',function(req,res){
	req.logout();
	req.flash('success_msg','You are logged out!');
	res.redirect('/users/login');
});

//Verify Token

function verifyToken(req, res, next){
	// Get auth header value
	const bearerHeader =req.headers['authorization'];
	// Check of bearer is undefined
	if(typeof bearerHeader !== 'undefined'){
		//Split at the space
		const bearer =bearerHeader.split(' ');
		//Get token from array
		const bearerToken =bearer[1];
		//Set the Token
		req.token =bearerToken;
		// Next middleware
		next();
	}else{
		// Forbiden
		res.sendStatus(403);
	}
}

module.exports= router;