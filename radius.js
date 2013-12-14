var Buffer = require('buffer').Buffer;
var Crypto = require('crypto');
var fs = require("fs");

exports.CreateResponse = function (msg, code, secret, avpList) {
    var r = new RadiusServerHelper(msg, secret);
    return r.CreateResponse(code, avpList);
};

exports.ParsePacket = function (msg, secret) {
    var r = new RadiusServerHelper(msg, secret);
    return r.ParsePacket(defAVPTypes);
};


exports.LoadDicts = function (cb) {
    var p = new pathHelper("dict", function (dicts) {
        var dIndex = 0;
        for (dIndex = 0; dIndex < dicts.length; dIndex++) {
            console.log("Loaded [" + dIndex + "] : " + dicts[dIndex].file);           
        }
        loadedDics = dicts;
        var dh = new dictHelper();
        defAVPTypes = dh.getDefaultAVPTypes();
        if (cb) {
            cb();
        }
    });
    p.LoadDicts();
};

var loadedDics = [];
var defAVPTypes = null;

var RadiusServerHelper = function (msg, secret) {
    var rs = this;
    rs.secret = secret;
    rs.Request = msg;
    rs.hasError = false;
    rs.Error = null;
    rs.endian = 'big';

    rs.CreateResponse = function (code, avpListIn) {
        var len = 20;
        if (avpListIn) {
            for (i = 0; i < avpListIn.length; i++) {
                var avp = avpListIn[i];
                var type = avp.type;
                var dh = new dictHelper();
                var davt = dh.getAvpByCode(defAVPTypes, type);
                var dataType = "string";
                if (davt == null) {
                    avp.rawData = new Buffer();
                    console.log("could not recognise avptype with code : " + type + " sending");
                }
                else {
                    dataType = davt.avptype;

                    if (type == 26) {

                        //pack VAS
                        //1. find the vendor first
                        if (!avp.vendorid) {
                            console.log("no vendor id specified for avptype :26");
                        }
                        else {
                            avp.rawData = rs.PackVSA(avp);
                        }
                    }
                    else {

                        if (dataType == 'integer') {
                            var s = 1;
                            if (avp.size) {
                                s = avp.size;
                            }
                            avp.rawData = rs.PackInt(parseInt(avp.value), s);
                        }
                        else if (dataType == 'ipaddr') {
                            avp.rawData = rs.PackIPAddress(avp.value);
                        }
                        else {
                            avp.rawData = rs.PackString(avp.value);
                        }


                    }
                }
                avp.length = 1 + 1 + avp.rawData.length;
                len = len + avp.length;
            }
        }
        var response = new Buffer(len);

        response[0] = code & 255;
        response[1] = rs.Request[1];


        response[3] = len & 255;
        response[2] = (len >> 8) & 255;

        //code + ID +length + reqAuth +secret
        var data = new Buffer(4);
        response.copy(data, 0, 0, 4);
        data = rs.Add(data, rs.Request.slice(4, 20));

        if (avpListIn) {
            for (i = 0; i < avpListIn.length; i++) {
                var avp = avpListIn[i];
                var codeOut = new Buffer(1);
                codeOut[0] = avp.type & 255;
                var lenOut = new Buffer(1);
                lenOut[0] = avp.length & 255;
                data = rs.Add(data, codeOut);
                data = rs.Add(data, lenOut);
                data = rs.Add(data, avp.rawData);
            }
        }
        data = rs.Add(data, rs.GetSecret());
        var hash = Crypto.createHash('md5').update(data).digest('hex');
        for (i = 0; i < 16; i++) {
            var h = hash.substring(2 * i, 2 * i + 2);
            response[4 + i] = parseInt(h, 16);
        }
        //avp list is not used in response yet.
        if (avpListIn) {
            var startIndex = 20;
            for (i = 0; i < avpListIn.length; i++) {
                var avp = avpListIn[i];
                response[startIndex] = avp.type & 255;
                response[startIndex + 1] = avp.length & 255;
                avp.rawData.copy(response, startIndex + 2, 0, avp.rawData.length);
                startIndex = startIndex + avp.length;
            }
        }
        if (rs.Error) {
            console.log('error creating response ' + rs.Error);
        }
        return response;
    };

    rs.Add = function (s1, s2) {
        var result = new Buffer(s1.length + s2.length);
        s1.copy(result, 0, 0, s1.length);
        s2.copy(result, s1.length, 0, s2.length);
        return result;
    };

    rs.GetSecret = function () {
        var s = new Buffer(rs.secret);
        return s;
    };

    rs.ProcessPassword = function (avp) {

        if (avp.length < 18) {
            rs.hasError = true;
            rs.Error = 'Invalid password : min length expected is 18. Found ' + avp.length;
            console.log(rs.Error);
            return avp;
        }

        if (avp.length > 130) {
            rs.hasError = true;
            rs.Error = 'Invalid password : max length expected is 130';
            console.log(rs.Error);
            return avp;
        }

        var passLen = avp.length - 2;
        if (passLen % 16 != 0) {
            rs.hasError = true;
            rs.Error = 'Invalid password :password length must be multiple of 16';
            console.log(rs.Error);
            return avp;
        }

        //All validations done.
        var lastVal = null;
        var S = rs.GetSecret();
        var plainPass = new Buffer(passLen);

        for (i = 0; i < passLen; i = i + 16) {
            var c = lastVal;
            if (i == 0) {
                c = rs.Request.slice(4, 20); //RA
            }
            var p = rs.Request.slice(avp.index + 2 + i, avp.index + 2 + i + 16);
            var data = rs.Add(S, c);
            var hash = Crypto.createHash('md5').update(data).digest('hex');
            var xor = new Buffer(16);
            for (j = 0; j < xor.length; j++) {
                var st = 2 * j;
                var d = hash.substring(st, st + 2);
                var d1 = parseInt(d, 16);
                xor[j] = p[j] ^ d1; // p[j] ^ hash[j];
                plainPass[16 * i + j] = xor[j];
            }

            lastVal = xor;

        }

        var index = plainPass.length;
        var nullByte = new Buffer(1);
        while (index > 0 && plainPass[index - 1] != 0 && plainPass[index - 1] != nullByte[0])
            index--;
        var passbuff = plainPass.slice(0, index);

        avp.value = passbuff.toString("utf8").replace(/\u0000/g, "");
        return avp;
    };

    rs.PackVSA = function (avp) {
        var dh = new dictHelper();
        var vendorDict = dh.getDictionaryVendorID(avp.vendorid);
        var rawVendorId = rs.PackInt(avp.vendorid, 4);


        var rawVendorData = new Buffer(0);
        if (vendorDict == null) {
            console.log("could not find a dictionary for vendor : " + vendorDict);

            //pack as string
            rawVendorData = rs.PackString(avp.value);
        }
        else {
            if (avp.VSA) {
                for (var v = 0; v < avp.VSA.length; v++) {
                    var vsacode = avp.VSA[v].type;
                    var vsatype = dh.getAvpByCode(vendorDict.attrs, vsacode).avptype;

                    console.log("Packing VSA : " + vsacode + " as " + vsatype);

                    var vsarawData = new Buffer(0);
                    if (vsatype == 'ipaddr') {
                        vsarawData = rs.PackIPAddress(avp.VSA[v].value);
                    }
                    else if (vsatype == 'integer') {
                        var s = 1;
                        if (avp.VSA[v].size) {
                            s = avp.VSA[v].size;
                        }
                        else {
                            console.log("no size specified for VSA :" + vsacode);
                        }
                        vsarawData = rs.PackInt(avp.VSA[v].value, s);
                    }
                    else {//default everything else to string
                        vsarawData = rs.PackString(avp.VSA[v].value);
                    }

                    //append to 
                    var vsaHead = new Buffer(2);
                    vsaHead[0] = rs.PackInt(vsacode, 1)[0];
                    var vsaLen = 2 + vsarawData.length;
                    vsaHead[1] = rs.PackInt(vsaLen, 1)[0];                  

                    rawVendorData = rs.Add(rawVendorData, vsaHead);
                    rawVendorData = rs.Add(rawVendorData, vsarawData);
                }
            }
            else {
                console.log("No vsa found for packing");
                rawVendorData = rs.PackString(avp.value);
            }
        }

        return rs.Add(rawVendorId, rawVendorData);
    };
    rs.ParseVSA = function (avp) {
        if (avp.type != 26) {
            return; //invalid call
        }

        var buff = rs.Request.slice(avp.index + 2, avp.index + avp.length);
        //http://technet.microsoft.com/en-us/library/cc958030.aspx

        avp.vendorid = buff.readUInt32BE(0);
        console.log("vendor id : " + avp.vendorid + " total buff len : " + buff.length);

        var dh = new dictHelper();
        var vendorDict = dh.getDictionaryVendorID(avp.vendorid);
        if (vendorDict == null) {
            console.log("could not find a dictionary for vendor : " + vendorDict);
            avp.vendordata = buff.slice(4, buff.length).toString();

        }
        else {
            //process specific attri.
            var remainingBuff = buff.slice(4); //ignore 4 : vendorId
            avp.VSA = [];
            var originalLen = remainingBuff.length;
            while (remainingBuff.length > 0) {

                console.log("remaining :" + remainingBuff.length);
                var vsCode = remainingBuff.readUInt8(0, rs.endian);
                var vsLen = remainingBuff.readUInt8(1, rs.endian);
                var vsaAttr = { "code": vsCode, "len": vsLen };
                if (vsLen > 2) {
                    var currBuff = remainingBuff.slice(2, vsLen);
                    var vsatype = dh.getAvpByCode(vendorDict.attrs, vsCode);

                    console.log("found vsatype :" + vsatype);
                    vsaAttr.name = vsatype.name;
                    vsaAttr.type = vsatype.avptype;
                    if (vsaAttr.type == 'ipaddr') {
                        vsaAttr.value = rs.ParseIPAddress(currBuff);
                    }
                    else if (vsaAttr.type == 'integer') {
                        vsaAttr.value = rs.ParseInt(currBuff);
                    }
                    else {//default everything else to string
                        vsaAttr.value = currBuff.toString();
                    }

                }
                console.log(vsaAttr);
                avp.VSA.push(vsaAttr);


                remainingBuff = remainingBuff.slice(vsLen);
                if (originalLen == remainingBuff.length) {
                    console.log("no parsing happened - Len : " + originalLen);
                    for (var b = 0; b < remainingBuff.length; b++) {
                        console.log("b[" + b + "] = " + remainingBuff[b]);
                    }
                    break;
                }
            }
        }



        return avp;


    };


    rs.ParsePacket = function (avpTypes) {

        var secretBuffer = new Buffer(secret);

        var p = {};


        p.Code = msg.readUInt8(0, rs.endian);
        p.Identifier = msg.readUInt8(1, rs.endian);
        p.Length = msg.readUInt16BE(2);

        p.Authenticator = msg.slice(4, 20).toString('hex', 0, 16);
        p.AVP = [];
        p.error = null;
        if (msg.Length < 20) {
            p.error = 'Invalid Request : Min message length should be 20';
        }
        if (msg.Length > 4094) {
            p.error = 'Invalid Request : Max message length is 4094';
        }
        if (p.Length > msg.length) {
            p.error = 'Invalid Request :  Length of message [' + msg.length + '] is less than expected length [' + p.Length + ']';
        }
        if (p.error != null)
            return p;

        var index = 20;
        var vendorId = 0;
        var maxIndex = p.Length;
        while (index < maxIndex) {
            var typ = msg.readUInt8(index, rs.endian);
            var len = msg.readUInt8(index + 1, rs.endian);
            var buff = msg.slice(index + 2, index + len);
            var val = buff.toString();
            var avp = { type: typ, length: len, value: val, index: index };
            index = index + avp.length;
            if (typ == 2) {
                rs.ProcessPassword(avp);
            }
            else if (typ == 26) {
                avp = rs.ParseVSA(avp);
                vendorId = avp.vendorid;
            }
            else {
                var dh = new dictHelper();

                var avpAttr = dh.getAvpByCode(avpTypes, avp.type);
                var dataType = 'string';
                if (avpAttr != null) {
                    dataType = avpAttr.avptype; //avpTypes[avp.type];
                    avp.name = avpAttr.name;
                }
                if (dataType == 'ipaddr') {
                    avp.value = rs.ParseIPAddress(buff);
                }
                else if (dataType == 'integer') {
                    avp.value = rs.ParseInt(buff);
                }
                else {
                    // treat rest as string until those types are implemented.
                    // octet types need to be handled in a specific way
                    if (dataType != 'string') {
                        if (dataType == 'octets') {
                            console.log('need to handle octet for avp type ' + avp.type + ' [' + dataType + '] defaulting to string');
                        } else if (dataType == null) {
                            console.log('we do not recognize avp type (null) ' + avp.type + ' [' + dataType + '] defaulting to string');
                        }
                        else {
                            console.log('we do not recognize avp type ' + avp.type + ' [' + dataType + '] defaulting to string');
                        }
                    }
                    try {
                        avp.value = buff.toString();
                    }
                    catch (e) { }
                }
            }

            p.AVP.push(avp);
        }




        return p;
    }

    rs.ParseIPAddress = function (buff) {
        var ip = "";
        for (i = 0; i < buff.length; i++) {
            ip = ip + buff.readUInt8(i, rs.endian);
            if (i != buff.length - 1) {
                ip = ip + ".";
            }
        }
        return ip;
    };

    rs.ParseInt = function (buff) {

        if (buff.length == 2) {
            return buff.readUInt16BE(0);
        } else if (buff.length == 4) {
            return buff.readUInt32BE(0); //why same?
        }

        return buff.readUInt8(0, rs.endian); //default
    };

    rs.PackInt = function (val, size) {
        var response = new Buffer(size);

        val = parseInt(val);

        if (size == 1) {
            response[0] = val & 255;
        }
        else if (size == 2) {
            response[1] = val & 255;
            response[0] = (val >> 8) & 255;
        }
        else if (size == 4) {
            response[3] = val & 255;
            response[2] = (val >> 8) & 255;

            var rem = val >> 8;
            response[1] = (rem >> 8) & 255;
            var rem2 = rem >> 8;
            response[0] = (rem2 >> 8) & 255;
        }

        return response;
    };

    rs.PackIPAddress = function (val) {
        var parst = val.split(".");
        var result = new Buffer(4);
        for (var i = 0; i < 4; i++) {
            result[i] = ParseInt(parst[1]) & 255;
        }
        return result;

    };

    rs.PackString = function (val) {
        return new Buffer(val);
    };

    return rs;
};


var pathHelper = function (dirName, cb) {
    var d = this;
    d.dir = dirName;
    d.callback = cb;


    d.LoadDicts = function () {
        var dicts = [];
        fs.readdir(d.dir, function (err, files) {           
            if (err) {
                console.log(err);
            }
            var findex = 0;
            for (findex = 0; findex < files.length; findex++) {
                var dp = new dictParser(d.dir + "/" + files[findex]);
                dicts.push(dp.parse());
            }
            if (cb) {
                cb(dicts);
            }
        });
    };

    return d;
};

var dictParser = function (fileName) {
    var p = this;
    p.file = fileName;

    p.parse = function () {
        var dic = new dict();
        dic.file = p.file;
        var lines = fs.readFileSync(p.file).toString().split('\n');
        var lIndex = 0;
        for (lIndex = 0; lIndex < lines.length; lIndex++) {
            var l = lines[lIndex];
            if (!l || l[0] == "" || l[0] == "#")//ignore blank and comments
                continue;

            var splt = p.getWords(l);

            if (l.slice(0, "VENDOR".length) == "VENDOR") {
                dic.header.VENDOR = splt[1];
                dic.header.CODE = splt[2];
                dic.header.Raw = l;
            }
            else if (l.slice(0, "ATTRIBUTE".length) == "ATTRIBUTE") {
                var att = {};
                att.type = splt[0];
                att.name = splt[1];
                att.avpcode = splt[2];
                att.avptype = splt[3];
                att.Raw = l;
                dic.attrs.push(att);
            }
            else if (l.slice(0, "VALUE".length) == "VALUE") {
                var v = {};
                v.type = splt[0];
                v.name = splt[1];
                v.algo = splt[2];
                v.code = splt[3];
                v.Raw = l;
                dic.vals.push(v);
            }
            else {
            }

        }
        return dic;
    };

    p.getWords = function (line) {
        var s = line.split('\t');
        var w = [];
        for (j = 0; j < s.length; j++) {
            if (s[j] != '\t' && s[j] != '') {
                w.push(s[j]);
            }
        }
        return w;
    };
    return p;
};

var dict = function () {
    var d = this;
    d.header = { "VENDOR": "VendorName", "CODE": 0 };
    d.attrs = [];
    d.vals = [];
    d.file = "";
    return d;
};

var dictHelper = function () {
    var dh = this;
    dh.getName = function (avpCode, vendorId) {
        var dictIndex = 0;
        for (dictIndex = 0; dictIndex < loadedDics.length; dictIndex++) {
            //ignore vendorid till implemented
            var d = loadedDics[dictIndex];
            // console.log("looking in : " + d.file);
            var attIndex = 0;
            for (attIndex = 0; attIndex < d.attrs.length; attIndex++) {
                // console.log("searching in : " + d.attrs[attIndex].avpcode);
                if (d.attrs[attIndex].avpcode == avpCode) {

                    return d.attrs[attIndex].name;
                }
            }
        };

        return avpCode;
    };
    dh.getDictionaryByName = function (name) {
        var ldictIndex = 0;
        for (ldictIndex = 0; ldictIndex < loadedDics.length; ldictIndex++) {
            if (loadedDics[ldictIndex].file == name)
                return loadedDics[ldictIndex];
        }
        console.log("could not find dictionary for name : " + name);
        return null;
    };
    dh.getDictionaryVendorID = function (vendorID) {
        var ldictIndex = 0;
        for (ldictIndex = 0; ldictIndex < loadedDics.length; ldictIndex++) {
            if (loadedDics[ldictIndex].header.CODE == vendorID)
                return loadedDics[ldictIndex];
        }
        console.log("could not find dictionary for vendorid : " + vendorID);
        return null;
    };

    dh.getDefaultAVPTypes = function () {
        var dict1 = dh.getDictionaryByName("dict/dictionary.rfc2865");
        var dict2 = dh.getDictionaryByName("dict/dictionary.rfc2866");
        var attributes = [];
        for (dict1Index = 0; dict1Index < dict1.attrs.length; dict1Index++) {
            attributes.push(dict1.attrs[dict1Index]);
        }
        for (dict2Index = 0; dict2Index < dict2.attrs.length; dict2Index++) {
            attributes.push(dict2.attrs[dict2Index]);
        }

        return attributes;

    };

    dh.getAvpByCode = function (avplist, code) {
        for (codeIndex = 0; codeIndex < avplist.length; codeIndex++) {
            if (avplist[codeIndex].avpcode == code) {
                return avplist[codeIndex];
            }
        }
        console.log("invalid code search  : " + code);
        return null;
    };

    return dh;
};
