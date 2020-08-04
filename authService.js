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
const db_config = process.env.CLEARDB_DATABASE_URL;

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
            console.log("Auth_Service no longer has a connection to db")
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
        let new_user_sql = "INSERT INTO `users` (`name`, `email`, `phone`) VALUES (\"" + non_user.name + "\",\"" + non_user.email + "\"," + non_user.phone + ")";
        connection.query(new_user_sql, function (err, result) {
            if (err) { throw err; }
            else {
                registered_id = result.insertId;
                encrypt(req.body.non_user_key).then(function (result) {
                    let new_key_sql = "INSERT INTO `keys` (`userId`, `key`, `username`) VALUES (" + registered_id + ", \"" + result + "\",\"" + non_user.username + "\")";
                    connection.query(new_key_sql, function (err, result) {
                        if (err) { throw err; }
                        else {
                            console.log("New User Alert!");
                            res.send({ registered_id });
                        };
                    });
                });
            }
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

    console.log("Verifying user credentials.....");

    try {
        let valid_user_sql = "SELECT `userId`, `key` FROM `keys` WHERE `username`= \"" + input_name + "\"";

        connection.query(valid_user_sql, function (err, result) {
            if (err) { throw err }
            else {
                if (result[0].key) {
                    check(input_key, result[0].key).then(function (isValid) {
                        if (isValid) {
                            res.send({ "valid": true, "valid_id": result[0].userId });
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