# Meta transaction

A meta transaction is a transaction made on behalf of someone else
This is usually done to give free transactions to the user and let the smart contract admin, platform or just anyone pay for them.

## How NOT-To
In Ethereum the address that signs the transaction has to pay for the gas, according to `gaslimit` and `gasprice` parameters.

If a user signs a proper transaction, sends it to someone else, and then another person pushes it to a node on the blockchain, the user still pays for the gas

## How To
Instead of having the user create a transaction, you need to have him form an array of parameters, sign that array with his wallet's private key, send this bundle of information to the dApp plaform and have someone else make a proper transaction to the smart contract using those parameters


## Code


### Javascript Client-side

The first step is having the client generate and sign a message. This message will contain all the parameters needed for the smart contrat function to work.
Imagene is a token transfer, in this case the parameters are:
- a 'from' address (as string, the address that signs the message)
- a 'to' address (as string)
- an amount (as int)
- a **nonce** (used to avoir replay attacks, more on this later)

``` javascript
var Web3    = require('web3')

function priv2address(priv) {
    let w3 = new Web3.Web3()
    return (w3.eth.accounts.privateKeyToAccount(priv, true)).address
}

async function signMessage (message, privkey) {
    let w3 = new Web3.Web3()
    var hash = Web3.utils.soliditySha3(...message);
    var signature = await w3.eth.accounts.sign(hash, privkey);
    return signature.signature;
}

let privatekey='0x5f4e4d44ca4d3c9ac8b8937cb6261a52fc24ce3c8cf6e8947ed99fb804e13984'
let address = priv2address(privatekey)
let message = [address, '0x9CAaAb96680D3fC3826dDf402503a7A3683e9710',65536, 20]
let signature = await signMessage(message, privatekey)

transferMessage2Server(message, signature)

```

- This code uses web3js library
- A private key is somehow defined locally
- The message is defined as an array of parameters
- **NOTE**: parameters type and order **do matter**
- Private key is used to sign the message
- The signature is attached to the message
- Message is sent to the javascript server (nodejs, express, bot....)

### Javascript Server-side

The server receives the message. Optionally (but strongly recommended) the server can do some checks on the parameters before attempting the transaction (to save gas)

``` javascript
function verifySignature (message, signature, signer) {
    let w3 = new Web3.Web3()
    let r = "^0x[a-f0-9]{"+(130).toString()+"}$";
    let regex = new RegExp(r,"i");
    if (signature.match(regex) === null) {
        return false
    }
    let message_hash = Web3.utils.soliditySha3(...message);
    let address =  w3.eth.accounts.recover(message_hash, signature, false);
    return address === signer;  // Beware, addresses could be case-sensitive
}

let {message, signature} = receiveMessageFromClient()
let signature_ok = verifySignature(message, signature, message[0])
if (signature_ok) {
    sendTransaction([...message, signature])
}
```
- The server receives a message and it's signature from the client
- The first parameter in the message is the sender so must be the signer
- The backend verifies that the sender (from) matches the signer
- If OK sends calls the smart contrac transaction and sends all


### Smart contract

The solidity part **requires** the method to work with meta-transactions

If the regular ERC20 transfer method is:

``` javascript
function transferFrom(address from, address to, uint256 value) public returns (bool success)
```

then the equivalent meta-transaction method must be:

``` javascript
function transferFromMeta(address from, address to, uint256 value, uint nonce, bytes memory signature) public returns (bool success)
```

Where:
- **_signature** is the signature mada on all previous 4 parameters with the private key of the user `_form`
- **_nonce** is a counter that increments +1 every call. This is needed to avoir replay attacks. Withoout this the user cannot be sure that his transaction will be run only once

The smart contract is somehow like this:

``` javascript
contract Token is ERC20 {
    mapping(address => uint256) public  NonceOfUser;

        /**
     * Checks that the provided nonce is valid for the user
     *
     *     @notice nonce can only increment value, like in regular eth transactions
     *     @notice avoids replay attack
     *     @notice reverts if invalid nonce
     *     @param  user address of user
     *     @param  nonce (uint)
     *     @return true se è valido (altrimenti va il revert)
     */
    function _isValidNonce(address user, uint256 nonce) internal returns (bool) {
        require(nonce > NonceOfUser[user], "Invalid nonce");
        NonceOfUser[user] = nonce;
        return true;
    }

    /**
     * extract signer address from signed messate
     *     @param _messagehash bytes32 hash of message (thats' what's signed)
     *     @param _signature bytes _signature, the signature that derives from web3.eth.sign()
     *     @return (address) of the signed of the message
     */
    function _recover(bytes32 _messagehash, bytes memory _signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Controlla la dimensione della firma
        if (_signature.length != 65) {
            return (address(0));
        }

        // Separa la firma nelle sue componenti base (r,s,v) (inline assembly)
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }

        // Controlla e corregge la versione della firma (0,1) => (27,28)
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return (address(0));
        }

        // Ritorna l'address firmatario
        // solium-disable-next-line arg-overflow
        return ecrecover(_messagehash, v, r, s);
    }

    function transferFromMeta(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) external whenNotPaused {
        // Check that this is a new transaction
        require(_isValidNonce(from, nonce), "Invalid nonce");

        // Extract signer form signature
        bytes32 messageHash = keccak256(abi.encodePacked(from, to, amount, nonce));
        bytes memory pre = abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash);
        messageHash = keccak256(pre);
        address signer = _recover(messageHash, signature);

        require(from == signer, "Wrog signer");
        require(balanceOf(signer, token_id) >= amount, "Amount too big");

        // Attempt transfer
        _safeTransferFrom(from, to, amount, "");
    }
}
```