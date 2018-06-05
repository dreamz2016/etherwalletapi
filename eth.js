'use strict';

var ethUtil = require('ethereumjs-util')
ethUtil.crypto = require('crypto');
var BigNumber = require('bignumber.js')
var http = require('http')

var customNode = function(){

    this.SERVERURL = 'http://127.0.0.1:8545';

    //this.SERVERURL = port ? srvrUrl + ':' + port : srvrUrl;
    if (false) {
        var authorization = 'Basic ' + btoa(httpBasicAuthentication.user + ":" + httpBasicAuthentication.password);
        this.config.headers['Authorization'] = authorization;
    }
}
var customNode = function(srvrUrl, port, httpBasicAuthentication) {
    this.SERVERURL = port ? srvrUrl + ':' + port : srvrUrl;
    if (httpBasicAuthentication) {
        var authorization = 'Basic ' + btoa(httpBasicAuthentication.user + ":" + httpBasicAuthentication.password);
        this.config.headers['Authorization'] = authorization;
    }
}
customNode.prototype.config = {
    headers: {
        'Content-Type': 'application/json; charset=UTF-8'
    }
};

customNode.prototype.getCurrentBlock = function(callback) {
    this.post({
        method: 'eth_blockNumber'
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: new BigNumber(data.result).toString() });
    });
}
customNode.prototype.getChainId = function(callback) {
    this.post({
        method: 'net_version'
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: parseInt(data.result) });
    });
}
customNode.prototype.getBalance = function(addr, callback) {
    this.post({
        method: 'eth_getBalance',
        params: [addr, 'pending']
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: { address: addr, balance: new BigNumber(data.result).toString() } });
    });
}
customNode.prototype.getTransaction = function(txHash, callback) {
    this.post({
        method: 'eth_getTransactionByHash',
        params: [txHash]
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: data.result });
    });
}
customNode.prototype.getTransactionData = function(addr, callback) {
    var response = { error: false, msg: '', data: { address: addr, balance: '', gasprice: '', nonce: '' } };
    var parentObj = this;
    var reqObj = [
        { "id": parentObj.getRandomID(), "jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, 'pending'] },
        { "id": parentObj.getRandomID(), "jsonrpc": "2.0", "method": "eth_gasPrice", "params": [] },
        { "id": parentObj.getRandomID(), "jsonrpc": "2.0", "method": "eth_getTransactionCount", "params": [addr, 'pending'] }
    ];
    this.rawPost(reqObj, function(data) {
        for (var i in data) {
            if (data[i].error) {
                callback({ error: true, msg: data[i].error.message, data: '' });
                return;
            }
        }
        response.data.balance = new BigNumber(data[0].result).toString();
        response.data.gasprice = data[1].result;
        response.data.nonce = data[2].result;
        callback(response);
    });
}
customNode.prototype.sendRawTx = function(rawTx, callback) {
    this.post({
        method: 'eth_sendRawTransaction',
        params: [rawTx]
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: data.result });
    });
}
customNode.prototype.getEstimatedGas = function(txobj, callback) {
    console.log(txobj.value)
    txobj.value = ethFuncs.trimHexZero(txobj.value);
    this.post({
        method: 'eth_estimateGas',
        params: [{ from: txobj.from, to: txobj.to, value: txobj.value, data: txobj.data }]
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: data.result });
    });
}
var ethCallArr = {
    calls: [],
    callbacks: [],
    timer: null
};
customNode.prototype.getEthCall = function(txobj, callback) {
    var parentObj = this;
    if (!ethCallArr.calls.length) {
        ethCallArr.timer = setTimeout(function() {
            parentObj.rawPost(ethCallArr.calls, function(data) {
                ethCallArr.calls = [];
                var _callbacks = ethCallArr.callbacks.slice();
                ethCallArr.callbacks = [];
                for (var i in data) {
                    if (data[i].error) _callbacks[i]({ error: true, msg: data[i].error.message, data: '' });
                    else _callbacks[i]({ error: false, msg: '', data: data[i].result });
                }
            });
        }, 500);
    }
    ethCallArr.calls.push({ "id": parentObj.getRandomID(), "jsonrpc": "2.0", "method": "eth_call", "params": [{ to: txobj.to, data: txobj.data }, 'pending'] });
    ethCallArr.callbacks.push(callback);
}
customNode.prototype.getTraceCall = function(txobj, callback) {
    this.post({
        method: 'trace_call',
        params: [txobj, ["stateDiff", "trace", "vmTrace"]]
    }, function(data) {
        if (data.error) callback({ error: true, msg: data.error.message, data: '' });
        else callback({ error: false, msg: '', data: data.result });
    });
}
customNode.prototype.rawPost = function(data, callback) {


    var data = JSON.stringify(JSON.stringify);


    var options = {

        host: this.SERVERURL,
        port: 8545,
        method: 'POST',
        headers:{
            'Content-Type':'application/json',
            'Content-Length':data.length
        }
    };

    var req = http.request(options, function(res) {

        console.log("statusCode: ", res.statusCode);

        console.log("headers: ", res.headers);

        var _data = '';

        res.on('data', function(chunk){
            _data += chunk;

        });

        res.on('end', function(){
            console.log("\n--->>\nresult:",_data)
        });
    });

    

    req.write(data);
    req.end();


    // ajaxReq.http.post(this.SERVERURL, JSON.stringify(data), this.config).then(function(data) {
    //     callback(data.data);
    // }, function(data) {
    //     callback({ error: true, msg: "connection error", data: "" });
    // });
}
customNode.prototype.getRandomID = function() {
    return globalFuncs.getRandomBytes(16).toString('hex');
}
customNode.prototype.post = function(data, callback) {
    data.id = this.getRandomID();
    data.jsonrpc = "2.0";
    this.rawPost(data, callback);
}


var etherUnits = function() {};
etherUnits.unitMap = {
	'wei': '1',
	'kwei': '1000',
	'ada': '1000',
	'femtoether': '1000',
	'mwei': '1000000',
	'babbage': '1000000',
	'picoether': '1000000',
	'gwei': '1000000000',
	'shannon': '1000000000',
	'nanoether': '1000000000',
	'nano': '1000000000',
	'szabo': '1000000000000',
	'microether': '1000000000000',
	'micro': '1000000000000',
	'finney': '1000000000000000',
	'milliether': '1000000000000000',
	'milli': '1000000000000000',
	'ether': '1000000000000000000',
	'kether': '1000000000000000000000',
	'grand': '1000000000000000000000',
	'einstein': '1000000000000000000000',
	'mether': '1000000000000000000000000',
	'gether': '1000000000000000000000000000',
	'tether': '1000000000000000000000000000000'
};
etherUnits.getValueOfUnit = function(unit) {
	unit = unit ? unit.toLowerCase() : 'ether';
	var unitValue = this.unitMap[unit];
	if (unitValue === undefined) {
		throw new Error(globalFuncs.errorMsgs[4] + JSON.stringify(this.unitMap, null, 2));
	}
	return new BigNumber(unitValue, 10);
};
etherUnits.fiatToWei = function(number, pricePerEther) {
	var returnValue = new BigNumber(String(number)).div(pricePerEther).times(this.getValueOfUnit('ether')).round(0);
	return returnValue.toString(10);
};

etherUnits.toFiat = function(number, unit, multi) {
	var returnValue = new BigNumber(this.toEther(number, unit)).times(multi).round(5);
	return returnValue.toString(10);
};

etherUnits.toEther = function(number, unit) {
	var returnValue = new BigNumber(this.toWei(number, unit)).div(this.getValueOfUnit('ether'));
	return returnValue.toString(10);
};
etherUnits.toGwei = function(number, unit) {
	var returnValue = new BigNumber(this.toWei(number, unit)).div(this.getValueOfUnit('gwei'));
	return returnValue.toString(10);
};
etherUnits.toWei = function(number, unit) {
	var returnValue = new BigNumber(String(number)).times(this.getValueOfUnit(unit));
	return returnValue.toString(10);
};

etherUnits.unitToUnit = function(number, from, to) {
	var returnValue = new BigNumber(String(number)).times(this.getValueOfUnit(from)).div(this.getValueOfUnit(to));
	return returnValue.toString(10);
};


var ethFuncs = function() {}
ethFuncs.gasAdjustment = 40;
ethFuncs.validateEtherAddress = function(address) {
    if (address.substring(0, 2) != "0x") return false;
    else if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) return false;
    else if (/^(0x)?[0-9a-f]{40}$/.test(address) || /^(0x)?[0-9A-F]{40}$/.test(address)) return true;
    else
        return this.isChecksumAddress(address);
}
ethFuncs.isChecksumAddress = function(address) {
    return address == ethUtil.toChecksumAddress(address);
}
ethFuncs.validateHexString = function(str) {
    if (str == "") return true;
    str = str.substring(0, 2) == '0x' ? str.substring(2).toUpperCase() : str.toUpperCase();
    var re = /^[0-9A-F]+$/g;
    return re.test(str);
}
ethFuncs.sanitizeHex = function(hex) {
    console.log('hex:' + hex)
    hex = hex.substring(0, 2) == '0x' ? hex.substring(2) : hex;
    if (hex == "") return "";
    return '0x' + this.padLeftEven(hex);
}
ethFuncs.trimHexZero = function(hex) {
    if (hex == "0x00" || hex == "0x0") return "0x0";
    hex = this.sanitizeHex(hex);
    hex = hex.substring(2).replace(/^0+/, '');
    return '0x' + hex;
}
ethFuncs.padLeftEven = function(hex) {
    hex = hex.length % 2 != 0 ? '0' + hex : hex;
    return hex;
}
ethFuncs.addTinyMoreToGas = function(hex) {
    hex = this.sanitizeHex(hex);
    return new BigNumber(ethFuncs.gasAdjustment * etherUnits.getValueOfUnit('gwei')).toString(16);
}
ethFuncs.decimalToHex = function(dec) {
    return new BigNumber(dec).toString(16);
}
ethFuncs.hexToDecimal = function(hex) {
    return new BigNumber(this.sanitizeHex(hex)).toString();
}
ethFuncs.contractOutToArray = function(hex) {
    hex = hex.replace('0x', '').match(/.{64}/g);
    for (var i = 0; i < hex.length; i++) {
        hex[i] = hex[i].replace(/^0+/, '');
        hex[i] = hex[i] == "" ? "0" : hex[i];
    }
    return hex;
}
ethFuncs.getNakedAddress = function(address) {
    return address.toLowerCase().replace('0x', '');
}
ethFuncs.getDeteministicContractAddress = function(address, nonce) {
    nonce = new BigNumber(nonce).toString();
    address = address.substring(0, 2) == '0x' ? address : '0x' + address;
    return '0x' + ethUtil.generateAddress(address, nonce).toString('hex');
}
ethFuncs.padLeft = function(n, width, z) {
    z = z || '0';
    n = n + '';
    return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
}
ethFuncs.getDataObj = function(to, func, arrVals) {
    var val = "";
    for (var i = 0; i < arrVals.length; i++) val += this.padLeft(arrVals[i], 64);
    return {
        to: to,
        data: func + val
    };
}
ethFuncs.getFunctionSignature = function(name) {
    return ethUtil.sha3(name).toString('hex').slice(0, 8);
};
ethFuncs.estimateGas = function(dataObj, callback) {
    var adjustGas = function(gasLimit) {
        if (gasLimit == "0x5209") return "21000";
        if (new BigNumber(gasLimit).gt(4000000)) return "-1";
        return new BigNumber(gasLimit).toString();
    }
    var customNode = new customNode(); 
    customNode.getEstimatedGas(dataObj, function(data) {
        if (data.error) {
            callback(data);
            return;
        } else {
            callback({
                "error": false,
                "msg": "",
                "data": adjustGas(data.data)
            });
        }
    });
}


var globalFuncs = function() {}
globalFuncs.lightMode = false;
globalFuncs.getBlockie = function(address) {
    return blockies.create({
        seed: address.toLowerCase(),
        size: 8,
        scale: 16
    }).toDataURL();
};

globalFuncs.errorMsgs = [
    'Please enter a valid amount.', // 0
    'Your password must be at least 9 characters. Please ensure it is a strong password. ', // 1
    'Sorry! We don\'t recognize this type of wallet file. ', // 2
    'This is not a valid wallet file. ', // 3
    'This unit doesn\'t exists, please use the one of the following units ', // 4
    'Please enter a valid address. ', // 5
    'Please enter a valid password. ', // 6
    'Please enter valid decimals (Must be integer, 0-18). ', // 7
    'Please enter a valid gas limit (Must be integer. Try 21000-4000000). ', // 8
    'Please enter a valid data value (Must be hex). ', // 9
    'Please enter a valid gas price. ', // 10 - NOT USED
    'Please enter a valid nonce (Must be integer).', // 11
    'Invalid signed transaction. ', // 12
    'A wallet with this nickname already exists. ', // 13
    'Wallet not found. ', // 14
    'Whoops. It doesn\'t look like a proposal with this ID exists yet or there is an error reading this proposal. ', // 15 - NOT USED
    'A wallet with this address already exists in storage. Please check your wallets page. ', // 16
    '(error_17) Insufficient balance. Your gas limit * gas price + amount to send exceeds your current balance. Send more ETH to your account or use the "Send Entire Balance" button. If you believe this is in error, try pressing generate again. Required (d+) and got: (d+). [Learn More.](https://myetherwallet.github.io/knowledge-base/transactions/transactions-not-showing-or-pending.html)', // 17
    'All gas would be used on this transaction. This means you have already voted on this proposal or the debate period has ended.', // 18
    'Please enter a valid symbol', // 19
    'Not a valid ERC-20 token', // 20
    'Could not estimate gas. There are not enough funds in the account, or the receiving contract address would throw an error. Feel free to manually set the gas and proceed. The error message upon sending may be more informative.', // 21
    'Please enter valid node name', // 22
    'Enter valid URL. If you are on https, your URL must be https', // 23
    'Please enter a valid port. ', // 24
    'Please enter a valid chain ID. ', // 25
    'Please enter a valid ABI. ', // 26
    'Minimum amount: 0.01. Max amount: ', // 27
    'You need this `Keystore File + Password` or the `Private Key` (next page) to access this wallet in the future. ', // 28
    'Please enter a valid user and password. ', // 29
    'Please enter a valid name (7+ characters, limited punctuation) ', // 30
    'Please enter a valid secret phrase. ', // 31
    'Could not connect to the node. Refresh your page, try a different node (top-right corner), check your firewall settings. If custom node, check your configs.', // 32
    'The wallet you have unlocked does not match the owner\'s address. ', // 33
    'The name you are attempting to reveal does not match the name you have entered. ', // 34
    'Input address is not checksummed. <a href="https://myetherwallet.github.io/knowledge-base/addresses/not-checksummed-shows-when-i-enter-an-address.html" target="_blank" rel="noopener noreferrer"> Click here to learn what this means.</a>', // 35
    'Please enter valid TX hash', // 36
    'Please enter valid hex string. Hex only contains: 0x, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, a, b, c, d, e, f', // 37
    'Offer must have either price or reserve set to more than 0', // 38
    'Bid must be more than the specified minimum', // 39
    'Please enter a valid private key' // 40
];


globalFuncs.scrypt = {
    n: 8192
};
globalFuncs.postDelay = 300;
globalFuncs.kdf = "scrypt";
globalFuncs.defaultTxGasLimit = 21000;
globalFuncs.defaultTokenGasLimit = 200000;
globalFuncs.donateAddress = "0xDECAF9CD2367cdbb726E904cD6397eDFcAe6068D";
globalFuncs.isNumeric = function(n) {
    return !isNaN(parseFloat(n)) && isFinite(n);
};
globalFuncs.urlGet = function(name) {
    name = name.toLowerCase();
    if (name = (new RegExp('[?&]' + encodeURIComponent(name) + '=([^&]*)')).exec(location.search.toLowerCase())) return this.stripTags(decodeURIComponent(name[1]));
};
globalFuncs.stripTags = function(str) {
    return xssFilters.inHTMLData(str);
};

globalFuncs.isStrongPass = function(password) {
    return password.length > 8;
};
globalFuncs.hexToAscii = function(hex) {
    return hex.match(/.{1,2}/g).map(function(v) {
        return String.fromCharCode(parseInt(v, 16));
    }).join('');
};
globalFuncs.isAlphaNumeric = function(value) {
    return !/[^a-zA-Z0-9]/.test(value);
};
globalFuncs.getRandomBytes = function(num) {
    return ethUtil.crypto.randomBytes(num);
};

globalFuncs.isAlphaNumericOrSpec = function(value) {
  return !/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]*$/.test(value);
}


var uiFuncs = function() {}
uiFuncs.getTxData = function($scope) {
    return {
        to: $scope.tx.to,
        value: $scope.tx.value,
        unit: $scope.tx.unit,
        gasLimit: $scope.tx.gasLimit,
        data: $scope.tx.data,
        from: $scope.wallet.getAddressString(),
        privKey: $scope.wallet.privKey ? $scope.wallet.getPrivateKeyString() : ''
    };
}
uiFuncs.isTxDataValid = function(txData) {
    if (txData.to != "0xCONTRACT" && !ethFuncs.validateEtherAddress(txData.to)) throw globalFuncs.errorMsgs[5];
    else if (!globalFuncs.isNumeric(txData.value) || parseFloat(txData.value) < 0) throw globalFuncs.errorMsgs[0];
    else if (!globalFuncs.isNumeric(txData.gasLimit) || parseFloat(txData.gasLimit) <= 0) throw globalFuncs.errorMsgs[8];
    else if (!ethFuncs.validateHexString(txData.data)) throw globalFuncs.errorMsgs[9];
    if (txData.to == "0xCONTRACT") txData.to = '';
}
uiFuncs.signTxTrezor = function(rawTx, txData, callback) {
    var localCallback = function(result) {
        if (!result.success) {
            if (callback !== undefined) {
                callback({
                    isError: true,
                    error: result.error
                });
            }
            return;
        }

        rawTx.v = "0x" + ethFuncs.decimalToHex(result.v);
        rawTx.r = "0x" + result.r;
        rawTx.s = "0x" + result.s;
        var eTx = new ethUtil.Tx(rawTx);
        rawTx.rawTx = JSON.stringify(rawTx);
        rawTx.signedTx = '0x' + eTx.serialize().toString('hex');
        rawTx.isError = false;
        if (callback !== undefined) callback(rawTx);
    }

    TrezorConnect.signEthereumTx(
        txData.path,
        ethFuncs.getNakedAddress(rawTx.nonce),
        ethFuncs.getNakedAddress(rawTx.gasPrice),
        ethFuncs.getNakedAddress(rawTx.gasLimit),
        ethFuncs.getNakedAddress(rawTx.to),
        ethFuncs.getNakedAddress(rawTx.value),
        ethFuncs.getNakedAddress(rawTx.data),
        rawTx.chainId,
        localCallback
    );
}
uiFuncs.signTxLedger = function(app, eTx, rawTx, txData, old, callback) {
    eTx.raw[6] = Buffer.from([rawTx.chainId]);
    eTx.raw[7] = eTx.raw[8] = 0;
    var toHash = old ? eTx.raw.slice(0, 6) : eTx.raw;
    var txToSign = ethUtil.rlp.encode(toHash);
    var localCallback = function(result, error) {
        if (typeof error != "undefined") {
            error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
            if (callback !== undefined) callback({
                isError: true,
                error: error
            });
            return;
        }
        rawTx.v = "0x" + result['v'];
        rawTx.r = "0x" + result['r'];
        rawTx.s = "0x" + result['s'];
        eTx = new ethUtil.Tx(rawTx);
        rawTx.rawTx = JSON.stringify(rawTx);
        rawTx.signedTx = '0x' + eTx.serialize().toString('hex');
        rawTx.isError = false;
        if (callback !== undefined) callback(rawTx);
    }
    app.signTransaction(txData.path, txToSign.toString('hex'), localCallback);
}
uiFuncs.signTxDigitalBitbox = function(eTx, rawTx, txData, callback) {
    var localCallback = function(result, error) {
        if (typeof error != "undefined") {
            error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
            if (callback !== undefined) callback({
                isError: true,
                error: error
            });
            return;
        }
        uiFuncs.notifier.info("The transaction was signed but not sent. Click the blue 'Send Transaction' button to continue.");
        rawTx.v = ethFuncs.sanitizeHex(result['v']);
        rawTx.r = ethFuncs.sanitizeHex(result['r']);
        rawTx.s = ethFuncs.sanitizeHex(result['s']);
        var eTx_ = new ethUtil.Tx(rawTx);
        rawTx.rawTx = JSON.stringify(rawTx);
        rawTx.signedTx = ethFuncs.sanitizeHex(eTx_.serialize().toString('hex'));
        rawTx.isError = false;
        if (callback !== undefined) callback(rawTx);
    }
    uiFuncs.notifier.info("Touch the LED for 3 seconds to sign the transaction. Or tap the LED to cancel.");
    var app = new DigitalBitboxEth(txData.hwTransport, '');
    app.signTransaction(txData.path, eTx, localCallback);
}
uiFuncs.signTxSecalot = function(eTx, rawTx, txData, callback) {

    var localCallback = function(result, error) {
        if (typeof error != "undefined") {
            error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
            if (callback !== undefined) callback({
                isError: true,
                error: error
            });
            return;
        }
        uiFuncs.notifier.info("The transaction was signed but not sent. Click the blue 'Send Transaction' button to continue.");
        rawTx.v = ethFuncs.sanitizeHex(result['v']);
        rawTx.r = ethFuncs.sanitizeHex(result['r']);
        rawTx.s = ethFuncs.sanitizeHex(result['s']);

        var eTx_ = new ethUtil.Tx(rawTx);
        rawTx.rawTx = JSON.stringify(rawTx);
        rawTx.signedTx = ethFuncs.sanitizeHex(eTx_.serialize().toString('hex'));
        rawTx.isError = false;
        if (callback !== undefined) callback(rawTx);
    }
    uiFuncs.notifier.info("Tap a touch button on your device to confirm signing.");
    var app = new SecalotEth(txData.hwTransport);
    app.signTransaction(txData.path, eTx, localCallback);
}
uiFuncs.trezorUnlockCallback = function(txData, callback) {
    TrezorConnect.open(function(error) {
        if (error) {
            if (callback !== undefined) callback({
                isError: true,
                error: error
            });
        } else {
            txData.trezorUnlocked = true;
            uiFuncs.generateTx(txData, callback);
        }
    });
}
uiFuncs.generateTx = function(txData, callback) {
    if ((typeof txData.hwType != "undefined") && (txData.hwType == "trezor") && !txData.trezorUnlocked) {
        uiFuncs.trezorUnlockCallback(txData, callback);
        return;
    }
    try {
        uiFuncs.isTxDataValid(txData);
        var genTxWithInfo = function(data) {
            var rawTx = {
                nonce: ethFuncs.sanitizeHex(data.nonce),
                gasPrice: data.isOffline ? ethFuncs.sanitizeHex(data.gasprice) : ethFuncs.sanitizeHex(ethFuncs.addTinyMoreToGas(data.gasprice)),
                gasLimit: ethFuncs.sanitizeHex(ethFuncs.decimalToHex(txData.gasLimit)),
                to: ethFuncs.sanitizeHex(txData.to),
                value: ethFuncs.sanitizeHex(ethFuncs.decimalToHex(etherUnits.toWei(txData.value, txData.unit))),
                data: ethFuncs.sanitizeHex(txData.data)
            }
            if (ajaxReq.eip155) rawTx.chainId = ajaxReq.chainId;
            rawTx.data = rawTx.data == '' ? '0x' : rawTx.data;
            var eTx = new ethUtil.Tx(rawTx);
            if ((typeof txData.hwType != "undefined") && (txData.hwType == "ledger")) {
                var app = new ledgerEth(txData.hwTransport);
                var EIP155Supported = false;
                var localCallback = function(result, error) {
                    if (typeof error != "undefined") {
                        if (callback !== undefined) callback({
                            isError: true,
                            error: error
                        });
                        return;
                    }
                    var splitVersion = result['version'].split('.');
                    if (parseInt(splitVersion[0]) > 1) {
                        EIP155Supported = true;
                    } else
                    if (parseInt(splitVersion[1]) > 0) {
                        EIP155Supported = true;
                    } else
                    if (parseInt(splitVersion[2]) > 2) {
                        EIP155Supported = true;
                    }
                    uiFuncs.signTxLedger(app, eTx, rawTx, txData, !EIP155Supported, callback);
                }
                app.getAppConfiguration(localCallback);
            } else if ((typeof txData.hwType != "undefined") && (txData.hwType == "trezor")) {
                uiFuncs.signTxTrezor(rawTx, txData, callback);
            } else if ((typeof txData.hwType != "undefined") && (txData.hwType == "web3")) {
                // for web3, we dont actually sign it here
                // instead we put the final params in the "signedTx" field and
                // wait for the confirmation dialogue / sendTx method
                var txParams = Object.assign({
                    from: txData.from,
                    gas: ethFuncs.sanitizeHex(ethFuncs.decimalToHex(txData.gasLimit)) // MetaMask and Web3 v1.0 use 'gas' not 'gasLimit'
                }, rawTx)
                rawTx.rawTx = JSON.stringify(rawTx);
                rawTx.signedTx = JSON.stringify(txParams);
                rawTx.isError = false;
                callback(rawTx)
            } else if ((typeof txData.hwType != "undefined") && (txData.hwType == "digitalBitbox")) {
                uiFuncs.signTxDigitalBitbox(eTx, rawTx, txData, callback);
            } else if ((typeof txData.hwType != "undefined") && (txData.hwType == "secalot")) {
                uiFuncs.signTxSecalot(eTx, rawTx, txData, callback);
            } else {
                eTx.sign(new Buffer(txData.privKey, 'hex'));
                rawTx.rawTx = JSON.stringify(rawTx);
                rawTx.signedTx = '0x' + eTx.serialize().toString('hex');
                rawTx.isError = false;
                if (callback !== undefined) callback(rawTx);
            }
        }
        if (txData.nonce || txData.gasPrice) {
            var data = {
                nonce: txData.nonce,
                gasprice: txData.gasPrice
            }
            data.isOffline = txData.isOffline ? txData.isOffline : false;
            genTxWithInfo(data);
        } else {
            ajaxReq.getTransactionData(txData.from, function(data) {
                if (data.error && callback !== undefined) {
                    callback({
                        isError: true,
                        error: e
                    });
                } else {
                    data = data.data;
                    data.isOffline = txData.isOffline ? txData.isOffline : false;
                    genTxWithInfo(data);
                }
            });
        }
    } catch (e) {
        if (callback !== undefined) callback({
            isError: true,
            error: e
        });
    }
}
uiFuncs.sendTx = function(signedTx, callback) {
    // check for web3 late signed tx
    if (signedTx.slice(0, 2) !== '0x') {
        var txParams = JSON.parse(signedTx)
        window.web3.eth.sendTransaction(txParams, function(err, txHash) {
            if (err) {
                return callback({
                    isError: true,
                    error: err.stack,
                })
            }
            callback({
                data: txHash
            })
        });
        return
    }

    ajaxReq.sendRawTx(signedTx, function(data) {
        var resp = {};
        if (data.error) {
            resp = {
                isError: true,
                error: data.msg
            };
        } else {
            resp = {
                isError: false,
                data: data.data
            };
        }
        if (callback !== undefined) callback(resp);
    });
}
uiFuncs.transferAllBalance = function(fromAdd, gasLimit, callback) {
    try {
        ajaxReq.getTransactionData(fromAdd, function(data) {
            if (data.error) throw data.msg;
            data = data.data;
            var gasPrice = new BigNumber(ethFuncs.sanitizeHex(ethFuncs.addTinyMoreToGas(data.gasprice))).times(gasLimit);
            var maxVal = new BigNumber(data.balance).minus(gasPrice);
            maxVal = etherUnits.toEther(maxVal, 'wei') < 0 ? 0 : etherUnits.toEther(maxVal, 'wei');
            if (callback !== undefined) callback({
                isError: false,
                unit: "ether",
                value: maxVal
            });
        });
    } catch (e) {
        if (callback !== undefined) callback({
            isError: true,
            error: e
        });
    }
}
uiFuncs.notifier = {
    alerts: {},
    warning: function(msg, duration = 5000) {
        this.addAlert("warning", msg, duration);
    },
    info: function(msg, duration = 5000) {
        this.addAlert("info", msg, duration);
    },
    danger: function(msg, duration = 7000) {
        msg = msg.message ? msg.message : msg;
        // Danger messages can be translated based on the type of node
        msg = globalFuncs.getEthNodeMsg(msg);
        this.addAlert("danger", msg, duration);
    },
    success: function(msg, duration = 5000) {
        this.addAlert("success", msg, duration);
    },
    addAlert: function(type, msg, duration) {
        if (duration == undefined) duration = 7000;
        // Save all messages by unique id for removal
        var id = Date.now();
        alert = this.buildAlert(id, type, msg);
        this.alerts[id] = alert
        var that = this;
        if (duration > 0) { // Support permanent messages
            setTimeout(alert.close, duration);
        }
        if (!this.scope.$$phase) this.scope.$apply();
    },
    buildAlert: function(id, type, msg) {
        var that = this;
        return {
            show: true,
            type: type,
            message: msg,
            close: function() {
                delete that.alerts[id];
                if (!that.scope.$$phase) that.scope.$apply();
            }
        }
    },
}


module.exports = {
    uiFuncs,
    globalFuncs,
    ethFuncs,
    etherUnits,
    customNode,
}
