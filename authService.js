// Set up
'use strict'
var argon2 = require('argon2');
var express = require('express');
var app = express();
var mysql = require('mysql');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var cors = require('cors');


// Configuration
var connection;
const db_config = require('./db_amazon_config.json');

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

function handleDisconnect() {
    connection = mysql.createConnection(db_config);

    connection.connect(function (err) {
        if (err) {
            console.log("Auth_Service has error connection to db: " + err);
            setTimeout(handleDisconnect, 2000);
        }
        console.log("Auth_Service is connected to db")
    });

    connection.on("error", function (err) {
        console.log("Auth_Service db error", err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            console.log("Auth_Service is reattempting database connection....")
            handleDisconnect();
        }
        else {
            console.log(err);
            console.log("Auth_Service no longer has a connection to db");
            handleDisconnect();;
        }
    });
}

handleDisconnect(); // starts database connection. 

// Start app and database connection and listen on port 6254  
app.listen(process.env.AUTH_PORT || 6200);
console.log("Auth Service listening on port  - ", (process.env.AUTH_PORT || 6200));

//ADD NEW USER TO SYSTEM
app.post('/auth/users', function (req, res) {

    var non_user = req.body.non_user;
    try {
        encrypt(req.body.non_user_key).then(function (result) {
            let new_user_sql = "CALL Add_new_user(\"" + non_user.name + "\",\"" + non_user.email + "\"," + non_user.phone +",\""+result+"\",\""+non_user.username+ "\")";
            connection.query(new_user_sql, function (err, result) {
                if (err) { throw err; }
                else {
                    let registered_user = result[0][0].user_id;
                    console.log("New User Alert! "+registered_user);
                    res.send({registered_user});
                };
            });
        });
    }
    catch (err) {
        console.log(err);
    }
})

//VERIFY USER CREDENTIALS
//requires username and password
app.get('/auth/users', function (req, res) {

    var input_name = req.query.input_name;
    var input_key = req.query.input_key;
    try {
        let valid_user_sql = "SELECT `user_id`, `key` FROM `keys` WHERE `username`= \"" + input_name + "\"";

        connection.query(valid_user_sql, function (err, result) {
            if (err) { throw err }
            else {
                if (result[0] != undefined) {
                    check(input_key, result[0].key).then(function (isValid) {
                        if (isValid) {
                            res.send({ "valid": true, "valid_id": result[0].user_id });
                        }
                        else {
                            res.send({ "valid": false, "valid_id": null });
                        }
                    })
                }
                else {
                    res.send({ "valid": false, "valid_id": null });
                }
            }
        })
    } catch (err) {
        console.log(err);
    }

});

//Methods

function encrypt(p) {

    try {
        let h = argon2.hash(p, {
            type: argon2.argon2i,
            memoryCost: 32,
            hashLength: 30,
        });
        return h;

    } catch (err) {
        throw err; //internal failure
    }

}

async function check(ui, hp) {
    try {
        if (await argon2.verify(hp, ui)) {
            return true // password match
        } else {
            return false // password did not match
        }
    } catch (err) {
        throw err // internal failure
    }
}