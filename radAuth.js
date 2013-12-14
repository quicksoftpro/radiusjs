var dgram = require("dgram");
var authServer = dgram.createSocket("udp4");
var radius = require('./radius');

authServer.on("message", function (msg, rinfo) {
    HandleIncomingAuthRequest(msg, rinfo,authServer, function () {
    });
});

authServer.on("listening", function () {
    var address = authServer.address();
    console.log("auth server listening " +
      address.address + ":" + address.port);
});

radius.LoadDicts(function () {
    authServer.bind(1812);
});

function HandleIncomingAuthRequest(msg, rinfo,server, callback) {

    var secret = "s3cr3t";

    var packet =  radius.ParsePacket(msg, secret);

    if (packet != null && packet.Code == 1) {
        var resCode = 3;

	// get important avps
	var username = '';
	var password = '';
	for (var i=0; i<packet.AVP.length; i++) {

		if (packet.AVP[i].type == 1) {
			username = packet.AVP[i].value;
		}

		if (packet.AVP[i].type == 2) {
			password = packet.AVP[i].value;
		}

	}

	var avps = [];
	// RFC2869 Acct-Interim-Interval type 85 int
	// 600 seconds, 10 minutes
	var avp = { type: 85, value: 600 };
	avps.push(avp);

	if (username == 'myuser' && password == 'mypass') {
		// valid login
		var response = radius.CreateResponse(msg, 2, secret, avps);
		server.send(response, 0, response.length, rinfo.port, rinfo.address);
		console.log('valid login');
	} else {
		// invalid login
		var response = radius.CreateResponse(msg, 3, secret);
		server.send(response, 0, response.length, rinfo.port, rinfo.address);
		console.log('invalid login');
	}

	if (callback)
		callback();
    }
}
