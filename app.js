var assert = require('assert')
var Wallet = require('./wallet.js')
var Thirdparty = require('./thirdparty.js')
var globalFuncs = require('./globalFuncs.js')
var solc = require('solc')
var fs = require("fs");
var express = require('express');
var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');
var bearerToken = require('express-bearer-token');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var ethFuncs = require('./ethFuncs.js');
var Web3 = require ('web3')
var uiFuncs = require('./uiFuncs.js');
var customNode = require('./customNode.js');
var etherUnits = require('./etherUnits.js');
var Validator = require('./validator.js')
var ethUtil = require('ethereumjs-util')
ethUtil.solidityUtils = require('./solidity/utils');
ethUtil.solidityCoder = require('./solidity/coder');
var BigNumber = require('bignumber.js');

var app = express();



//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
	extended: false
}));

// // set secret variable
// app.set('secret', 'thisismysecret');
// app.use(expressJWT({
// 	secret: 'thisismysecret'
// }).unless({
// 	path: ['/users']
// }));
// app.use(bearerToken());
// app.use(function(req, res, next) {
// 	logger.debug(' ------>>>>>> new request for %s',req.originalUrl);
// 	if (req.originalUrl.indexOf('/users') >= 0) {
// 		return next();
// 	}

// 	var token = req.token;
// 	jwt.verify(token, app.get('secret'), function(err, decoded) {
// 		if (err) {
// 			res.send({
// 				success: false,
// 				message: '无效的token'
// 			});
// 			return;
// 		} else {
// 			// add the decoded user name and org name to the request object
// 			// for the downstream code to use
//             req.username = decoded.username;
//             req.pwd = decoded.pwd
//             if(req.username == decoded.username && req.pwd == decoded.pwd){
//                 res.send({
//                     success: false,
//                     message: '用户名或密码错误'
//                 });
//                 return;
//             }
            
// 			return next();
// 		}
// 	});
// });

// app.post('/users', async function(req, res) {
//     var username = req.body.username;
//     var pwd = req.body.pwd;

// 	logger.debug('End point : /users');
//     logger.debug('User name : ' + username);
    
// 	if (!username) {
// 		res.json(getErrorMessage('\'username\''));
// 		return;
// 	}
// 	if (!pwd) {
// 		res.json(getErrorMessage('\'pwd\''));
// 		return;
// 	}
// 	var token = jwt.sign({
// 		exp: Math.floor(Date.now() / 1000) + 1440
// 		username: username,
// 		pwd: pwd
//     }, app.get('secret'));
    
//     response.token = token;
//     res.json(response);
// });

app.get('/', function (req, res) {
  res.send('Welcome to EtherWalletApi!');
});



//生成新钱包
app.get('/genNewWallet', function(req, res){

    var pwd = req.query.pwd
    console.log('pwd:' + pwd)

    try{

        console.log(pwd.length);

        if(pwd.length <= 8){
            throw '密码必须大于8位'
        }

        var wallet = Wallet.generate()
        var toV3 = wallet.toV3String(pwd, {
            kdf: 'scrypt',
            n: 8192
        })

        var filename = wallet.getV3Filename()
        var address = wallet.getAddressString()
        var privatekey = wallet.getPrivateKeyString();

        //给该地址转移
        var web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

        var coinbase = '0x64ceb333bef77e97524f442c5b255271df5dc519'

        var unlock = web3.personal.unlockAccount(coinbase, '123456789')
        console.log('unlock:' + unlock)
        if(unlock){
            web3.eth.sendTransaction(
                {
                    from:coinbase,
                    to: address,
                    value:web3.toWei(100,'ether')
                }
            )
        }

        return res.status(200).json(
        {
            address:address,
            privatekey:privatekey,
            filename:filename,
            v3:toV3
        });

    }catch(e){
        return res.status(500).json(
            {
                error: e
            });
    }

});


//编译合约
app.get('/compile', function(req, res){

    try{

        var web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));

        var input = fs.readFileSync('./contract/HelloWorldContract.sol');
        // Setting 1 as second paramateractivates the optimiser
        var output = solc.compile(input.toString(), 1)

        for (var contractName in output.contracts) {
            // code and ABI that are needed by web3
            console.log(contractName + '-bytecode: ' + output.contracts[contractName].bytecode)
            console.log(contractName + '-abi:' + JSON.stringify(output.contracts[contractName].interface));

            var bytecode = output.contracts[contractName].bytecode;
            var abi = output.contracts[contractName].interface;
        }

        fs.writeFile("./contract/HelloWorldContract.JSON", abi, function(err) {
            if(err) {
                throw new Error(err)
            }

            console.log("ABI Saved");
        });

        return res.status(200).json(
            {
                bytecode:bytecode,
                abi:JSON.parse(abi),
            }
        );

    }catch(e){

        return res.status(500).json(
            {
                error: e
            }
        );
        
    }

});

//部署合约
app.post('/deploy', function(req, res){

    var symbol = req.body.symbol
    var name = req.body.name
    var intro = req.body.intro

    //先导入keystore
    var pwd = req.body.pwd;
    var keystore = req.body.keystore;
    var bytecode = req.body.bytecode;

    console.log('symbol:' + symbol)
    console.log('name:' + name)
    console.log('intro:' + intro)
    console.log('pwd:' + pwd)
    console.log('keystore:' + keystore)
    console.log('bytecode:' + bytecode)


    var $scope = {}

    try{

        $scope.wallet = Wallet.fromV3(keystore, pwd)

        var address = $scope.wallet.getAddressString()
    

        console.log('account_address:' + address);
        console.log("Deploying the contract");

        $scope.tx = {
            data: bytecode,
            unit:'ether',
            value: 0,
            to: ''
        }

        var estObj = {
            from: $scope.wallet != null ? $scope.wallet.getAddressString() : globalFuncs.donateAddress,
            value: ethFuncs.sanitizeHex(ethFuncs.decimalToHex(etherUnits.toWei($scope.tx.value, $scope.tx.unit))),
            data: ethFuncs.sanitizeHex($scope.tx.data)
        };

        //console.log('extobj:' + JSON.stringify(estObj))

        if ($scope.tx.to != '') estObj.to = $scope.tx.to;

        ethFuncs.estimateGas(estObj, function (data) {

            $scope.tx.gasLimit = data.data;

            $scope.tx.data = ethFuncs.sanitizeHex($scope.tx.data);

            var CustomNode = new customNode('127.0.0.1', '8545')
            CustomNode.getTransactionData($scope.wallet.getAddressString(), function (data) {
                if (data.error){
                    throw new Error(data.error);
                } 

                data = data.data;
                $scope.tx.to = $scope.tx.to == '' ? '0xCONTRACT' : $scope.tx.to;
                $scope.tx.contractAddr = $scope.tx.to == '0xCONTRACT' ? ethFuncs.getDeteministicContractAddress($scope.wallet.getAddressString(), data.nonce) : '';
                //console.log('scope:' + $scope)
                var txData = uiFuncs.getTxData($scope);

                //console.log('txData:' + JSON.stringify(txData));

                uiFuncs.generateTx(txData, function (rawTx) {
                    if (!rawTx.isError) {
                        $scope.rawTx = rawTx.rawTx;
                        $scope.signedTx = rawTx.signedTx;
                        //console.log('scope-rawTx:' + $scope.rawTx)
                        //console.log('scope-signedTx:' + $scope.signedTx)
                        $scope.showRaw = true;

                        uiFuncs.sendTx($scope.signedTx, function (resp) {

                            if (!resp.isError) {

                                return res.status(200).json(
                                    {
                                        Txhash: resp.data,
                                        contractAddr: $scope.tx.contractAddr,
                                    }
                                );

                                console.log('Txhash:' + resp.data)
                                console.log('contractAddress:' + $scope.tx.contractAddr)
                                //console.log(JSON.stringify(resp))
                            } else {
                                throw new Error(resp.error)
                            }
                        });

                    } else {
                        throw new Error(rawTx)
                    }                
                });
            });
        });
    }catch(e){
        return res.status(500).json(
            {
                error: e
            }
        );
    }
});



//查看交易
app.get('/getTransaction', function(req, res){

    var txhash = req.query.txhash;
    var MIN_GAS = 41;
    var txStatus = {
        found: 0,
        notFound: 1,
        mined: 2
    };

    var txInfo = {
        status: null, // notFound foundInPending foundOnChain
        hash: txhash,
        from: '',
        to: '',
        value: '',
        valueStr: '',
        gasLimit: '',
        gasPrice: '',
        data: '',
        nonce: ''
    };


    try {

        if (!Validator.isValidTxHash(txhash)) throw globalFuncs.errorMsgs[36];
        var CustomNode = new customNode('127.0.0.1', '8545')
        CustomNode.getTransaction(txhash, function (data) {
            if (data.error){
                return res.status(500).json({error: data.msg});
            }else {
                var tx = data.data
                if (tx) {
                    console.log('txToObject');
                    console.log(tx);
                    var txInfo = {
                        status: tx.blockNumber ? txStatus.mined : txStatus.found,
                        hash: tx.hash,
                        from: ethUtil.toChecksumAddress(tx.from),
                        to: tx.to ? ethUtil.toChecksumAddress(tx.to) : '',
                        value: new BigNumber(tx.value).toString(),
                        valueStr: etherUnits.toEther(tx.value, 'wei') + " ETH",
                        gasLimit: new BigNumber(tx.gas).toString(),
                        gasPrice: {
                            wei: new BigNumber(tx.gasPrice).toString(),
                            gwei: new BigNumber(tx.gasPrice).div(etherUnits.getValueOfUnit('gwei')).toString(),
                            eth: etherUnits.toEther(tx.gasPrice, 'wei')
                        },
                        data: tx.input == '0x' ? '' : tx.input,
                        nonce: new BigNumber(tx.nonce).toString()
                    };

                    return res.status(200).json(
                        {
                            error: null,
                            data: txInfo,
                        }
                    );

                } else {
                    throw new Error('Tx Not Found')
                }
            }
        });
    } catch (e) {
        return res.status(500).json(
            {
                error: e
            }
        );
    }
});

app.get('/get', function(req, res){

    var contractAddress = req.query.contractAddress;
    var index = req.query.funcindex

    try{

        var YingshouABI = fs.readFileSync("./contract/HelloWorldContract.JSON");
        var abi = JSON.stringify(JSON.parse(YingshouABI))
        console.log('contractAddress:' + contractAddress)
        if (!Validator.isValidAddress(contractAddress)){
            throw globalFuncs.errorMsgs[5];
        }else if (!Validator.isJSON(abi)){
            throw globalFuncs.errorMsgs[26];
        }

        $functions = [];
        var tAbi = JSON.parse(abi);
        //console.log(tAbi)
        for (var i in tAbi) {
            if (tAbi[i].type == "function") {
                tAbi[i].inputs.map(function (i) {
                    i.value = '';
                });
                $functions.push(tAbi[i]);
            }
        }

        console.log('functions:' + JSON.stringify($functions))
        $selectedFunc = { name: $functions[index].name, index: index };
        if (!$functions[index].inputs.length) {

            var curFunc = $functions[$selectedFunc.index];
            var fullFuncName = ethUtil.solidityUtils.transformToFullName(curFunc);
            var funcSig = ethFuncs.getFunctionSignature(fullFuncName);
            var typeName = ethUtil.solidityUtils.extractTypeName(fullFuncName);
            var types = typeName.split(',');
            types = types[0] == "" ? [] : types;
            var values = [];

            console.log('curFunc:' + JSON.stringify(curFunc))
            for (var i in curFunc.inputs) {
                if (curFunc.inputs[i].value) {
                    if (curFunc.inputs[i].type.indexOf('[') !== -1 && curFunc.inputs[i].type.indexOf(']') !== -1){
                        values.push(curFunc.inputs[i].value.split(',')); 
                    }else{
                        values.push(curFunc.inputs[i].value);
                    }
                }else{
                    values.push('');
                }
            }

            console.log('values:' + values);
            var encodedata = '0x' + funcSig + ethUtil.solidityCoder.encodeParams(types, values);

            var CustomNode = new customNode('127.0.0.1', '8545')
            CustomNode.getEthCall({ to: contractAddress, data: encodedata }, function (data) {
                if (!data.error) {
                    var curFunc = $functions[$selectedFunc.index];
                    var outTypes = curFunc.outputs.map(function (i) {
                        return i.type;
                    });
                    var decoded = ethUtil.solidityCoder.decodeParams(outTypes, data.data.replace('0x', ''));
                    for (var i in decoded) {
                        if (decoded[i] instanceof BigNumber){
                            curFunc.outputs[i].value = decoded[i].toFixed(0);
                        }else{
                            curFunc.outputs[i].value = decoded[i];
                        }
                    }
                    
                    return res.status(200).json(
                        {
                            error: null,
                            data: curFunc,
                        }
                    );

                } else{
                    throw data.msg;
                }
            });
        }
    } catch(e) {

        return res.status(500).json(
            {
                error: e,
            }
        );
    }
});

//设置资产数量
app.post('/call', function(req, res){

    var valuestr = req.body.valuestr;
    var pwd = req.body.pwd;
    var keystore = req.body.keystore;
    var contractAddress = req.body.contractAddress;
    var index = req.body.funcindex

    var $scope = {}

    try{

        $scope.wallet = Wallet.fromV3(keystore, pwd)

        var YingshouABI = fs.readFileSync("./contract/HelloWorldContract.JSON");
        var abi = JSON.stringify(JSON.parse(YingshouABI))
        
        console.log('contractAddress:' + contractAddress)
        if (!Validator.isValidAddress(contractAddress)){
            throw globalFuncs.errorMsgs[5];
        }else if (!Validator.isJSON(abi)){
            throw globalFuncs.errorMsgs[26];
        }

        $functions = [];
        var tAbi = JSON.parse(abi);
        //console.log(tAbi)
        for (var i in tAbi) {
            if (tAbi[i].type == "function") {
                tAbi[i].inputs.map(function (i) {
                    i.value = '';
                });
                $functions.push(tAbi[i]);
            }
        }

        var curFunc = $functions[index];
        var fullFuncName = ethUtil.solidityUtils.transformToFullName(curFunc);
        console.log(fullFuncName)
        var funcSig = ethFuncs.getFunctionSignature(fullFuncName);
        var typeName = ethUtil.solidityUtils.extractTypeName(fullFuncName);
        var types = typeName.split(',');
        types = types[0] == "" ? [] : types;
        var values = [];
        //values.push(supply)

        values.push(valuestr.split(','));

        
        console.log(JSON.stringify(values))
        var encodeData = '0x' + funcSig + ethUtil.solidityCoder.encodeParams(types, values);

        console.log('encodeData:' + encodeData)

        $scope.tx = {
            data: '',
            unit:'ether',
            value: 0,
            to: contractAddress
        }


        $scope.tx.data = encodeData;

        var estObj = {
            from: $scope.wallet != null ? $scope.wallet.getAddressString() : globalFuncs.donateAddress,
            value: ethFuncs.sanitizeHex(ethFuncs.decimalToHex(etherUnits.toWei($scope.tx.value, $scope.tx.unit))),
            data: ethFuncs.sanitizeHex($scope.tx.data)
        };


        ethFuncs.estimateGas(estObj, function (data) {

            $scope.tx.gasLimit = data.data;

            $scope.tx.data = ethFuncs.sanitizeHex($scope.tx.data);

            var CustomNode = new customNode('127.0.0.1', '8545')
            CustomNode.getTransactionData($scope.wallet.getAddressString(), function (data) {
                if (data.error){
                    throw new Error(data.error);
                } 

                data = data.data;
                $scope.tx.to = $scope.tx.to == '' ? '0xCONTRACT' : $scope.tx.to;
                $scope.tx.contractAddr = $scope.tx.to == '0xCONTRACT' ? ethFuncs.getDeteministicContractAddress($scope.wallet.getAddressString(), data.nonce) : '';
                //console.log('scope:' + $scope)
                var txData = uiFuncs.getTxData($scope);

                //console.log('txData:' + JSON.stringify(txData));

                uiFuncs.generateTx(txData, function (rawTx) {
                    if (!rawTx.isError) {
                        $scope.rawTx = rawTx.rawTx;
                        $scope.signedTx = rawTx.signedTx;
                        //console.log('scope-rawTx:' + $scope.rawTx)
                        //console.log('scope-signedTx:' + $scope.signedTx)
                        $scope.showRaw = true;

                        uiFuncs.sendTx($scope.signedTx, function (resp) {

                            if (!resp.isError) {

                                return res.status(200).json(
                                    {
                                        Txhash: resp.data,
                                        contractAddr: $scope.tx.contractAddr,
                                    }
                                );

                                console.log('Txhash:' + resp.data)
                                console.log('contractAddress:' + $scope.tx.contractAddr)
                                //console.log(JSON.stringify(resp))
                            } else {
                                throw new Error(resp.error)
                            }
                        });

                    } else {
                        throw new Error(rawTx)
                    }                
                });
            });
        });
    }catch(e){
        return res.status(500).json(
            {
                error: e
            }
        );
    }
});

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;
  
    console.log('Example app listening at http://%s:%s', host, port);
  });
