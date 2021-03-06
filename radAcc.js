var dgram = require("dgram");
var accServer = dgram.createSocket("udp4");
var radius = require('./radius');
var conf = require("./conf.js").config;



accServer.on("message", function (msg, rinfo) {
    HandleIncomingAccRequest(msg, rinfo, accServer, function () {
    });
});

accServer.on("listening", function () {
    var address = accServer.address();
    console.log("acc server listening " +
      address.address + ":" + address.port);
});

radius.LoadDicts(function () {
    accServer.bind(conf.radaccport);
});

function HandleIncomingAccRequest(msg, rinfo, server,callback) {

	var secret = conf.radsecret;

	var packet = radius.ParsePacket(msg, secret);

	console.log(packet);

	var response = radius.CreateResponse(msg, 5, secret);
	server.send(response, 0, response.length, rinfo.port, rinfo.address);

	if (callback)
		callback();

}
