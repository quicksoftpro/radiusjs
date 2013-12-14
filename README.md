radiusjs
========

Implementation of RADIUS protocol using nodejs


radiusjs is a blazingly fast non blocking Radius server in pure JS

radiusjs was developed to provide a library which gives code level access to typical functions of a RADIUS server.

A code level interface to Radius which provides event handlers for recieved Radius packets and methods to send/reply allows you to completely customize authentication and accounting schemes. Our initial drive in creating this project was to use a mongodb database as the backend of Radius.

##License

The MIT License (MIT) Copyright (c) 2013 QuickSoftPro.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

##Requirements

Tested with node v0.10.20

##Example

Look at radAcc.js and radAuth.js for example Accounting and Authentication server implementations.

##Usage

AVP type 26 (vendorids)

AVP type 26 is a container type which holds AVP's for specific vendor id's.

ParsePacket will automatically deliver these values on incoming packets.

For sending packets:

var avps = [];

var avp = { type: 26, vendorid: 14988 };
avp.VSA = [];
var vsa = { type: 8, value: 'string value' };
avp.VSA.push(vsa);
avps.push(avp);
Current Limitations

Only supports auth login for cleartext (AVP type 2 User-Password), no CHAP or other variants (yet!)
Can only send AVP pairs in string format, however we can read all types
