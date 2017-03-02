/**
 * "Jennifer" HipChat bot implementation
 * @author Marek Ulwański <marek@ulwanski.pl>
 *
 * ngrok http 4000
 *
 * HipChat API getting started guide:
 * The comprehensive HipChat API reference can be found here: https://www.hipchat.com/docs/apiv2
 *
 * Modelled on Jennifer Love Hewitt ;)
 */

var _           = require('lodash');
var fs          = require('fs');
var ssl = {
    key: fs.readFileSync('./ssl/default.key'),
    cert: fs.readFileSync('./ssl/default.crt'),
    requestCert: true,
    rejectUnauthorized: false
};
var express     = require('express');
var bodyParser  = require('body-parser');
var bunyan      = require('bunyan');
var request     = require('request');
var jwtUtil     = require('jwt-simple');
var moment      = require('moment');
var mysql       = require('mysql');
var logs        = require('./logs.js');
var app         = require('express')();
var http        = require('http');
var https       = require('https').createServer(ssl, app);
var logger      = bunyan.createLogger({name: 'hc-sample-addon', level: 'info'});
var gis         = require('g-image-search');
var weather     = require('weather-js');

// @TODO: Move database config to separate file (and add this file to .gitignore)
var db = mysql.createConnection({
    host     : 'localhost',
    port     : '3306',
    user     : 'jennifer',
    password : 'TPV9XVh8JCaQ8NY5',
    database : 'jennifer',
    charset  : 'utf8_polish_ci'
});

var installationCache = [];

// Store for API access tokens, used when making REST calls to HipChat
var accessTokenStore = {};

var remoteLogsContent = [];

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

db.connect(function(error) {

    if (error) {
        logs.error(error.message);
        return false;
    }

    logs.info("MySQL Database connected (" + db.config.host + ":" + db.config.port + ") ID:" + db.threadId);

    var port = parseInt(process.argv[2], 10) || process.env.SERVER_PORT || 4000;
    var server = https.listen(port, function () {
        logs.info('Web server stared on port ' + port);
        logs.success("Jennifer HipChat Bot is ready ...");
    });

    server.on('error', function(error){
        logs.error(error.message);
        process.exit(error.code);
    });

    // db.destroy();
});

function substituteHostName(file, req, callback) {
    fs.readFile(file, function (err, data) {
        var content = _.template(data, {
            host: 'https://' + req.headers.host
        });
        callback(content);
    });
}

function sendDescriptor(file, req, res) {
    substituteHostName(file, req, function (content) {
        res.set('Content-Type', 'application/json');
        res.send(content);
    });
}

function sendHtml(file, req, res) {
    substituteHostName(file, req, function (content) {
        res.set('Content-Type', 'text/html');
        res.send(content);
    });
}

app.get('/descriptor', function (req, res) {
    sendDescriptor('capabilities-descriptor.json', req, res);
});

app.post('/installed', function (req, res) {
    var installation = req.body;

    logs.info('New installation started ... ');

    db.query('INSERT INTO `installation_store` SET ?', installation, function(error, result) {
        if (error) {
            logs.error(error.message);
            return error.code;
        }

        var id = result.insertId;

        // Retrieve the capabilities document
        var capabilitiesUrl = installation['capabilitiesUrl'];
        request.get(capabilitiesUrl, function (err, response, body) {
            var capabilities = JSON.parse(body);
            var oauthId = installation['oauthId'];

            var update = {
                tokenUrl: capabilities['capabilities']['oauth2Provider']['tokenUrl'],       // Save the token endpoint URL along with the client credentials
                apiUrl:   capabilities['capabilities']['hipchatApiProvider']['url']         // Save the API endpoint URL along with the client credentials
            };

            db.query("UPDATE `installation_store` SET ? WHERE `id` = ?", [update, id], function(error, result){
                if (error) {
                    logs.error(error.message);
                } else {
                    logs.success("Bot installed ...");
                    sendCustomMessage(oauthId, installation['roomId'], 'Cześć, mam na imię <i>Jennifer</i> jestem botem Divante, będe Wam od dzisiaj umilać czas w tym pokoju :) Gdyby ktoś mnie potrzebował niech wpiszę "<i>/jen help</i>" ;)', "green", "html");
                }
            });

        });

        res.sendStatus(200);
    });

});

app.get('/uninstalled', function (req, res) {
    var redirectUrl = req.query['redirect_url'];
    var installable_url = req.query['installable_url'];

    logs.info('New uninstalling started ... ');

    request.get(installable_url, function (err, response, body) {
        var installation = JSON.parse(body);

        installationCache[installation['oauthId']] = null;

        db.query("DELETE FROM `installation_store` WHERE `oauthId` = ?", installation['oauthId'], function(error, result){
            if (error) {
                logs.error(error.message);
            } else {
                logs.success("Bot uninstalled ...");
            }
        });

        // Redirect back to HipChat to complete the uninstallation
        res.redirect(redirectUrl);
    });
});

function isExpired(accessToken) {
    return accessToken.expirationTimeStamp < Date.now();
}

function refreshAccessToken(oauthId, callback) {

    db.query('SELECT * FROM `installation_store` WHERE `oauthId` = ?', [oauthId], function (error, results) {

        var installation = results[0];

        installationCache[oauthId] = installation;

        var params = {

            // The token url was discovered through the capabilities document
            uri: installation.tokenUrl,

            // Basic auth with OAuth credentials received on installation
            auth: {
                username: installation['oauthId'],
                password: installation['oauthSecret']
            },

            // OAuth dictates application/x-www-form-urlencoded parameters
            // In terms of scope, you can either to request a subset of the scopes declared in the add-on descriptor
            // or, if you don't, HipChat will use the scopes declared in the descriptor
            form: {
                grant_type: 'client_credentials',
                scope: 'send_notification'
            }
        };

        request.post(params, function (err, response, body) {
            var accessToken = JSON.parse(body);
            accessTokenStore[oauthId] = {
                // Add a minute of leeway
                expirationTimeStamp: Date.now() + ((accessToken['expires_in'] - 60) * 1000),
                token: accessToken
            };
            callback(accessToken);
        });

    });
}

function getAccessToken(oauthId, callback) {
    var accessToken = accessTokenStore[oauthId];
    if (!accessToken || isExpired(accessToken)) {
        refreshAccessToken(oauthId, callback);
    } else {
        process.nextTick(function () {
            callback(accessToken.token);
        });
    }
}

/**
 * Sending messages to HipChat rooms
 * ---------------------------------
 * You send messages to HipChat rooms via a REST call to the room notification endpoint
 * HipChat supports various formats for messages, and here are a few examples:
 */

function sendMessage(oauthId, roomId, message) {

    //console.log(oauthId);
    //console.log(roomId);

    var send = function(oauthId, notificationUrl, msg){
        getAccessToken(oauthId, function (token) {
            request.post(notificationUrl, {
                auth: {
                    bearer: token['access_token']
                },
                json: msg
            }, function (err, response, body) {
                //logger.info(err || response.statusCode, notificationUrl);
                //logger.info(response);
            });
        });
    }

    if(installationCache[oauthId] !== undefined && installationCache[oauthId] != null){
        var installation = installationCache[oauthId];
        var notificationUrl = installation.apiUrl + 'room/' + roomId + '/notification';
        send(oauthId, notificationUrl, message);
    } else {
        db.query('SELECT * FROM `installation_store` WHERE `oauthId` = ?', [oauthId], function (error, results) {
            var installation = results[0];
            var notificationUrl = installation.apiUrl + 'room/' + roomId + '/notification';
            installationCache[oauthId] = installation;
            send(oauthId, notificationUrl, message);
        });
    }
}

function sendTextMessage(oauthId, roomId, text) {
    var message = {
        color: 'gray',
        message: text,
        message_format: 'text'
    };
    sendMessage(oauthId, roomId, message)
}

function sendHtmlMessage(oauthId, roomId, text) {
    var message = {
        color: 'gray',
        message: text,
        message_format: 'html'
    };
    sendMessage(oauthId, roomId, message)
}

function sendCustomMessage(oauthId, roomId, text, color, format) {
    var message = {
        color: color,
        message: text,
        message_format: format
    };
    sendMessage(oauthId, roomId, message)
}

function sendErrorMessage(oauthId, roomId, text) {
    var message = {
        color: 'red',
        message: text,
        message_format: 'html'
    };
    sendMessage(oauthId, roomId, message)
}

function sendSimpleCardMessage(oauthId, roomId, title, msg) {
    var message = {
        color: 'gray',
        message: msg,
        message_format: 'html',
        card: {
            "style": "application",
            "id": "0",
            "url": "http://",
            "title": title,
            "description": msg,
        }
    };
    sendMessage(oauthId, roomId, message);
}

function sendSampleCardMessage(oauthId, roomId, description) {
    var message = {
        color: 'gray',
        message: 'this is a backup message for HipChat clients that do not understand cards (old HipChat clients, 3rd party XMPP clients)',
        message_format: 'text',
        card: {
            "style": "application",
            "id": "some_id",
            "url": "http://www.stuff.com",
            "title": "Such awesome. Very API. Wow!",
            "description": description,
            "thumbnail": {
                "url": "http://i.ytimg.com/vi/8M7Qie4Aowk/hqdefault.jpg"
            }
        }
    };
    sendMessage(oauthId, roomId, message);
}

function sendWelcomeCardMessage(oauthId, roomId, description) {
    var message = {
        color: 'gray',
        message: 'this is a backup message for HipChat clients that do not understand cards (old HipChat clients, 3rd party XMPP clients)',
        message_format: 'text',
        card: {
            "style": "application",
            "id": "some_id",
            "url": "http://www.stuff.com",
            "title": "Such awesome. Very API. Wow!",
            "description": description,
            "thumbnail": {
                "url": "http://i.ytimg.com/vi/8M7Qie4Aowk/hqdefault.jpg"
            }
        }
    };
    sendMessage(oauthId, roomId, message);
}

/**
 * Securing your add-on with JWT
 * -----------------------------
 * Whenever HipChat makes a call to your add-on (webhook, glance, views), it passes a JSON Web Token (JWT).
 * Depending on the scenario, it is either passed in the "signed_request" URL parameter, or the "Authorization" HTTP header.
 * This token contains information about the context of the call (OAuth ID, room ID, user ID, etc.)
 * This token is signed, and you should validate the signature, which guarantees that the call really comes from HipChat.
 * You validate the signature using the shared secret sent to your add-on at installation.
 *
 * It is implemented as an Express middleware function which will be executed in the call chain for every request the add-on receives from HipChat
 * It extracts the context of the call from the token (room ID, oauth ID) and adds them to a local variable accessible to the rest of the call chain.
 */

function validateJWT(req, res, next) {
    try {
        //Extract the JWT token
        var encodedJwt = req.query['signed_request'] ||req.headers['authorization'].substring(4) ||req.headers['Authorization'].substring(4);

        // Decode the base64-encoded token, which contains the oauth ID and room ID (to identify the installation)
        var jwt = jwtUtil.decode(encodedJwt, null, true);
        var oauthId = jwt['iss'];
        var roomId = jwt['context']['room_id'];

        db.query('SELECT `oauthSecret` FROM `installation_store` WHERE `oauthId` = ?', [oauthId], function (error, results) {


            // TODO: Poprawić obsługę błedów
            //if(error != null) throw new Exception(error);

            var oauthSecret = results[0].oauthSecret;

            // Validate the token signature using the installation's OAuth secret sent by HipChat during add-on installation
            // (to ensure the call comes from this HipChat installation)
            jwtUtil.decode(encodedJwt, oauthSecret);

            // All good, it's from HipChat, add the context to a local variable
            res.locals.context = {oauthId: oauthId, roomId: roomId};

            // Continue with the rest of the call chain
            next();
        });

    } catch (err) {
        logger.error(err);
        res.sendStatus(403);
    }
}

function imageSearch(res, cmd, message){

    // var mention = message['item']['message']['from']['mention_name'];
    var name = message['item']['message']['from']['name'];
    var word = cmd.slice(1).join(' ');

    gis(word).then(function logResults(results) {

        var top = results.splice(-30);
        var i = 0;

        do {
            var rand = top[Math.floor(Math.random() * top.length)];
            var end = rand.slice(-4);
            i++;
        } while(end != 'jpeg' && end != '.jpg' && end != '.png' && i < 10);

        logs.debug('Image found (' + i + ' time) for "' + word + '": ' + rand);
        sendTextMessage(res.locals.context.oauthId, res.locals.context.roomId, rand.replace('https://', 'http://') );

    }).catch(function(err){
        console.log(err);
    });

}

function sendJoke(res, cmd, message){

    var mention = message['item']['message']['from']['mention_name'];
    var name = message['item']['message']['from']['name'];
    var param = cmd.slice(1).join(' ');

    if(param) mention = param.replace("@", "");

    db.query('SELECT * FROM `jokes` ORDER BY RAND() LIMIT ?', [1], function (error, results) {

        var joke = results[0].content;

        //joke = joke.replace(new RegExp("\n", 'g'), '<br>');
        joke = joke.replace(new RegExp('mentionName', 'g'), "" + mention + "");

        sendTextMessage(res.locals.context.oauthId, res.locals.context.roomId, joke);
    });

}

function showWeather(res, cmd, message){

    var word = cmd.slice(1).join(' ');

    console.log(word);

    if(word == "" || word == null){
        word = "WROCLAW, PL";
    }

    weather.find({search: word, degreeType: 'C'}, function(err, result) {
        if(err){
            sendErrorMessage(res.locals.context.oauthId, res.locals.context.roomId, "Nie udało mi się pobrać pogody, spróbuj za chwilkę :)");
            logs.error(err);
            return false;
        }

        var data = result[0];
        if(data === undefined || data == null){
            sendErrorMessage(res.locals.context.oauthId, res.locals.context.roomId, "Nie udało mi się pobrać pogody, spróbuj za chwilkę :)");
            return 0;
        }

        var current = data.current;
        var city = data.location.name;
        var title = "Pogoda dla " + city;
        var msg = "Temperatura: " + current.temperature + "°C, wilgotność: " + current.humidity + "%, prędkość wiatru: " + current.windspeed;

        if(current.temperature < -5){
            var temp_msg = "Jest tak zimno że wróble przymarzają do gałęzi :o";
        } else if(current.temperature < 0){
            var temp_msg = "Czapki i rękawiczki mogą się przydać.";
        } else if(current.temperature < 5){
            var temp_msg = "Pora poszukać tego wełnianego swetra od babci :p";
        } else if(current.temperature < 10){
            var temp_msg = "Ciepła bluza może się dzisiaj przydać :)";
        } else if(current.temperature < 15){
            var temp_msg = "Mogło by być dzisiaj troszkę cieplej :)";
        } else if(current.temperature < 20){
            var temp_msg = "Jak ktoś nie lubi upałów, to dzisiaj będzie zadowolony :p";
        } else if(current.temperature < 22){
            var temp_msg = "Idealna temperatura na spacer!";
        } else if(current.temperature < 25){
            var temp_msg = "Ciepełko, ciepełko :D";
        } else if(current.temperature <= 27){
            var temp_msg = "Lato daje o sobie znać :)";
        } else if(current.temperature < 29){
            var temp_msg = "Polecam coś chłodnego do picia :p";
        } else if(current.temperature < 32){
            var temp_msg = "W centrum zwijają podobno asfalt, bo się zaczyna topić :o";
        } else if(current.temperature < 35){
            var temp_msg = "Żal się leje z nieba, czy to już apokalipsa? :o";
        } else {
            var temp_msg = "Umrzemy wszyscy! :(";
        }

        sendSimpleCardMessage(res.locals.context.oauthId, res.locals.context.roomId, title, msg + " \n" + temp_msg);
    });


}

function sendPsrHelp(res, cmd, message){

    var send_file = function(err, data){
        if(err){
            sendErrorMessage(res.locals.context.oauthId, res.locals.context.roomId, "Wystąpił nieznany błąd.");
            return false;
        }
        sendCustomMessage(res.locals.context.oauthId, res.locals.context.roomId, data, 'purple', 'html');
        return true;
    }

    switch(cmd[0]){

        case 'psr':
        case 'psr1':
            fs.readFile('./public/resources/help/psr/psr1.html', 'utf8', send_file);
            break;

        case 'psr2':
            fs.readFile('./public/resources/help/psr/psr2.html', 'utf8', send_file);
            break;

        case 'psr3':
            fs.readFile('./public/resources/help/psr/psr3.html', 'utf8', send_file);
            break;

        case 'psr4':
            fs.readFile('./public/resources/help/psr/psr4.html', 'utf8', send_file);
            break;
    }

}

app.post('/cmd', validateJWT, function (req, res) {

    var message = req.body;
    var cmd = message['item']['message']['message'].split(' ').slice(1);

    switch(cmd[0]){

        case 'img':
            imageSearch(res, cmd, message);
            res.sendStatus(204);
            break;

        case 'joke':
            sendJoke(res, cmd, message);
            res.sendStatus(204);
            break;

        case 'solid':
        case 'psr':
        case 'psr1':
        case 'psr2':
        case 'psr3':
        case 'psr4':
            sendPsrHelp(res, cmd, message);
            res.sendStatus(204);
            break;

        case 'weather':
            showWeather(res, cmd, message);
            res.sendStatus(204);
            break;

        case 'note': // Tworzenie notatek na później
            break;

        case 'zbluzgaj':
        case 'bluzgaj':
            break;

        case 'roomId':
            sendTextMessage(res.locals.context.oauthId, res.locals.context.roomId, "Current room ID: " + res.locals.context.roomId);
            res.sendStatus(204);
            break;

        case 'help':
            sendTextMessage(res.locals.context.oauthId, res.locals.context.roomId, "Tobie już nic nie pomoże ;)");
            res.sendStatus(204);
            break;

        default:
            sendTextMessage(res.locals.context.oauthId, res.locals.context.roomId, message['item']['message']['from']['name'] + " nie ma takiego polecenia, coś Ci się pomieszało :p");
            res.sendStatus(204);
    }

    //var echoMessage = "<i>" + mention + "</i> you send command: " + cmd[0] ;

});

/**
 * Add-on configuration page
 * -------------------------
 * Post installation, your add-on can show the user a configuration page
 * Your add-on declares it in its capability descriptor
 *    "configurable": {
 *            "url": "${host}/configure"
 *      }
 */

app.get('/configure', validateJWT, function (req, res) {
    sendHtml('/public/configure.html', req, res);
});

/**
 * HipChat Glance
 * --------------
 * To contribute a Glance to the HipChat right sidebar, declare it in the add-on descriptor
 * "glance": [
 *            {
 *				"icon": {
 *					"url": "${host}/resources/img/icon.png",
 *					"url@2x": "${host}/resources/img/icon.png"
 *				},
 *				"key": "sample-glance",
 *				"name": {
 *					"value": "Sample Glance"
 *				},
 *				"queryUrl": "${host}/glance-data",
 *				"target": "sample-sidebar"
 *			}
 *        ]
 * This contributes a glance to the sidebar. When the user clicks on it, it opens a view.
 *
 * When a user first opens a HipChat room where the add-on is installed, the HipChat client app
 * makes a REST call to the queryURL provided to get the initial value for the glance.
 * You can then update the glance for a room at any time by making a REST call to HipChat.
 * HipChat will then make sure glances are updated for all connected HipChat users.
 **/

// The queryURL endpoint specified in the capabilities descriptor
app.get('/glance-data', validateJWT, function (req, res) {

    // Handle CORS headers (cross domain request)
    res.header("Access-Control-Allow-Origin", "*");

    // Return glance data
    var sampleGlanceData = {
        label: {
            value: "<b>Hello</b> World",
            type: "html"
        }
    };
    res.send(JSON.stringify(sampleGlanceData));
});

// The queryURL endpoint specified in the capabilities descriptor
app.get('/remote-logs', validateJWT, function (req, res) {

    // Handle CORS headers (cross domain request)
    res.header("Access-Control-Allow-Origin", "*");

    // Return glance data
    var sampleGlanceData = {
        label: {
            value: "Remote logs",
            type: "html"
        }
    };
    res.send(JSON.stringify(sampleGlanceData));
});

app.get('/log', function (req, res){

    //Handle CORS headers (cross domain request)
    res.header("Access-Control-Allow-Origin", "*");

    console.log(req.query);

    //sendTextMessage(req.query.oauthId, req.query.roomId, req.query.msg);

    /*error_log
    facility
    host
    level
    message
    remote_addr
    request_path
    request_verb
    server
    source*/

    //remoteLogsContent[req.query.roomId][] = req.query.msg;

    res.send("ok");
});

//How to update glance data
function updateGlanceData(oauthId, roomId, glanceData) {

    db.query('SELECT * FROM `installation_store` WHERE `oauthId` = ?', [oauthId], function (error, results) {

        var installation = results[0];
        var roomGlanceUpdateUrl = installation.apiUrl + 'addon/ui/room/' + roomId;

        getAccessToken(oauthId, function (token) {
            request.post(roomGlanceUpdateUrl, {
                auth: {
                    bearer: token['access_token']
                },
                json: {
                    glance: [{
                        key: "sample-glance",
                        content: glanceData
                    }]
                }
            }, function (err, response, body) {
            });
        });

    });

}

//We'll trigger a glance update from the sidebar (check sidebar.html)
app.post('/update-glance', validateJWT, function (req, res) {
    var request = req.body;

    var glanceData = {
        label: {
            value: request.glanceText,
            type: "html"
        }
    };
    updateGlanceData(res.locals.context.oauthId, res.locals.context.roomId, glanceData);

    res.sendStatus(204);
});

app.get('/remote-logs-sidebar', validateJWT, function (req, res) {
    res.redirect('/remote-logs-sidebar.html');
});

app.get('/remote-logs-content', validateJWT, function (req, res) {

    var data = remoteLogsContent[res.locals.context.roomId];

    if(data !== undefined){
        res.send(JSON.stringify(data));
    } else {

    }

    res.send("empty");
});

// To send a message to the room from a sidebar view, there are a few options.
// Typically your add-on front-end makes a REST call to your add-on backend,
// passing information about the context (OAuth ID, room ID). Your add-on backend can then lookup
// an access token to use to post the message.
app.post('/post-card', validateJWT, function (req, res) {
    var request = req.body;
    sendSampleCardMessage(res.locals.context.oauthId, res.locals.context.roomId, req.body.cardDescription);
    res.sendStatus(204);
});

app.get('/dialog', validateJWT, function (req, res) {
    res.redirect('/dialog.html');
});

/*
 * Start the add-on
 */
app.all('*', function (req, res) {
    res.sendStatus(204);
});
