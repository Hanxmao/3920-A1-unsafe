require('./utils');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)


/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl:`mongodb+srv://${mongodb_user}:${mongodb_password}@3920-a1.rhwrzv7.mongodb.net/?retryWrites=true&w=majority`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (!isValidSession(req)) {
		req.session.destroy();
		res.redirect('/');
		return;
	}
	else {
		next();
	}
}

app.get('/', (req,res) => {
    if(req.session.username==undefined){
        res.render("index", {showName: false});
    } else {
        res.render("index", {showName: true, username: req.session.username});
    }
   
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});


app.get('/signup', (req,res) => {
    var missing = req.query.missing??-1;
    res.render("signup", {missing:missing});
});


app.get('/login', (req,res) => {
    var bad = req.query.bad??0;
    res.render("login", {bad:bad});
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;
    let missing = -1
    if(password.length<=0 || !password){
        missing=0
    } 
    if(!username){
        missing=1
    }
    if(!username&&!password){
        missing=2
    }


    if (missing<0){
        var hashedPassword = bcrypt.hashSync(password, saltRounds);

        var success = await db_users.createUser({ user: username, hashedPassword: hashedPassword });
    
        if (success) {
            req.session.authenticated = true;
            req.session.username = username;
            req.session.cookie.maxAge = expireTime;
            res.redirect("/members");
        }
        else {
            res.render("errorMessage", {error: "Failed to create user."} );
        }
    } else{
        res.redirect(`/signup?missing=${missing}`)
    }

});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;
    // '; INSERT INTO user (username, password) VALUES ('hacker', 'hacker');--


    var results = await db_users.getUser({ user: username });

    if (results) {
        if (results.length == 1) { //there should only be 1 user in the db that matches
            if (bcrypt.compareSync(password, results[0].password)) {
                req.session.authenticated = true;
                req.session.username = username;
                req.session.cookie.maxAge = expireTime;
                res.redirect('/');
                return;
            }
            else {
                console.log("invalid password");
            }
        }
        else {
            console.log('invalid number of users matched: '+results.length+" (expected 1).");
            res.redirect('/login?bad=1');
            return;            
        }
    }

    console.log('user not found');
    //user and password combination not found
    res.redirect("/login?bad=1");
});

app.use('/members', sessionValidation);

app.get('/members', (req,res) => {
    const randNum = Math.floor(Math.random() * 3) + 1;
    res.render("members", {username: req.session.username, randNum:randNum});
});

app.get('/logout', function(req, res) {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 