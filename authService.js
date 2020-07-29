import { anchrEncrypt } from './anchrCrypt.js';
import { User } from './objectFactory.js'
// Set up
var express = require('express');
var app = express();
var mysql = require('mysql');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var cors = require('cors');
var encrytion = anchrEncrypt();


// Configuration
var con = mysql.createConnection({
    host:"us-cdbr-east-02.cleardb.com",
    user:"bf13fc36dcfd85",
    password:"8d75886d",
})

app.use(bodyParser.urlencoded({ 'extended': 'true' }));
app.use(bodyParser.json());
app.use(bodyParser.json({ type: 'application/vnd.api+json' }));
app.use(methodOverride());
app.use(cors());

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'DELETE, POST, PUT');
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// Start app and listen on port 8080  
app.listen(process.env.PORT || 6254);
console.log("Auth server listening on port  - ", (process.env.PORT || 6254));

//ADD NEW USER TO SYSTEM
app.post('/auth/users', function (req, res) {

    let non_user = req.body.non_user;
    let non_user_key = encryption.encrypt(req.body.non_user_key);
    let registered_id = null;

    con.connect( function (err) {
        if(err){ throw err; }
        else{

            let new_user_sql = "INSERT INTO `users` (`name`, `email`, `phone`) VALUES (`"+non_user.name+"`,`"+non_user.email+"`,"+non_user.phone+")";
            con.query(new_user_sql, function (err, result){
                if (err){throw err;}
                else{
                    registered_id = result.insertId
                }
            });

            let new_key_sql = "INSERT INTO `keys` (`userId`, `key`, `username`) VALUES (`"+registered_id+"`,`"+non_user_key+"`,"+non_user.username+")";
            con.query(new_key_sql, function (err, result){
                if(err){throw err;}
                else{
                    console.log("New User Alert!");
                    res.send(registered_id);
                }
            })

        }
    })
})

//VERIFY USER CREDENTIALS
//requires username and password
//UNFINISHED*****
app.get('/auth/users', function (req, res) {

    let user = req.body.user;
    let user_input_key = req.body.key;

    console.log("Verifying user credentials.....");
    
    con.connect(function (err) {
        if (err){
            throw err;
        }
        else{
            let sql = "SELECT `userId`, `key` FROM `keys` WHERE `username`= `" + user + "`";
            con.query(sql, function (err, result){
                if(err) { throw err; }
                else{
                    let valid_key = result.key;
                    let valid = encrytion.check(user_input_key, valid_key);
                    if (valid){
                        res.send(result.userId);
                    }
                    else{
                        res.send("Credentials Invalid!");
                    }
                }
            });
        }
    })
});