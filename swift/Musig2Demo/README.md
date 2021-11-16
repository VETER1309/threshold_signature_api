# Overview

This is an example of using musig2 api for btc. Some help for building a threshold signature wallet for ios. In order to cope with the taproot upgrade, this api also provides the construction of taproot ordinary transactions and threshold wallet transactions.

# Dependencies

Step 1. Import package

`File>Add Packages>Github` search https://github.com/chainx-org/musig2-ios-api . The current version is **1.3.0**.

Step 2. Import
```
import Musig2
```

# Api

## Construct Tx

**generateRawTx(txids, indexs, addresses, amounts)**

~~~swift
Pass in the input and output list to construct the initial transaction
Returns: raw tx string.
~~~

**getSighash(prev_tx, tx, input_index, agg_pubkey, sigversion)**

~~~swift
Passing the previous transaction and the constructed transaction and the previous transaction outpoint index to calculate Sighash. 
agg_pubkey: aggregate pubkey, required when spending by threshold address. Pass in "" when spending by normal taproot address. 
sigversion: 0 or 1, 0 is normal taproot address, 1 is threshold address. 
Returns: sighash string.
Possible error string returned is Compute Sighash Fail.
~~~

**generateSchnorrSignature(message, privkey)**

~~~swift
Generate schnorr signature.
message: waiting for signed message. 
privkey: private key
Return the signature hex string. 
Possible error string returned is Invalid Signature.
~~~

**buildTaprootTx(tx, signature, input_index)**

~~~swift
Construct normal taproot address spending transaction.
tx: tx with at least one input and one output. 
signature: signature of sighash 
input_index: index of the input in base_tx.
Return the tx hex string. Possible error string returned is Construct Tx Fail.
~~~

**buildThresholdTx(tx, agg_signature, agg_pubkey, control, input_index)**

~~~swift
Construct Threshold address spending transaction.
tx: tx with at least one input and one output. 
agg_signature: aggregate signature of sighash 
agg_pubkey: signature corresponding to the aggregate public key. 
control: control script. 
input_index: index of the input in base_tx.
Return the tx hex string. 
Possible error string returned is Construct Tx Fail.
~~~

**getScriptPubkey(addr)**

~~~swift
Generate scirpt pubkey from address
addr: input address
Return the scirpt pubkey hex string. 
Possible error string returned is Invalid Address.
~~~

### Musig2
**getRound1State()**

```java
Generate the State of the first round
Returns: State Pointer 
If the calculation fails just a null pointer will be returned.
```

**getMyPrivkey(phrase, pd_passphrase)**

~~~
Generate private key from mnemonic
phrase: root phrase 
pd_passphrase: pass phrase
Returns: String. Return the private key hex string. Possible error string returned is Construct Secret Key.
~~~

**getMyPubkey(private)**

```java
Help to get the PublicKey from privkey
Returns: pubkey string 
Possible errors are Null KeyPair Pointer and Normal Error.
```

**getRound1Msg(state)**

```java
Passed round1 State to generate msg which will broadcast
Returns: msg String. 
Possible errors are Normal Error and Null Round1 State Pointer.
```

**encodeRound1State(state)**

```java
encode State object.
Returns: state String 
Possible error is Null Round1 State Pointer or Encode Fail.
```

**decodeRound1State(round1_state)**

```java
Use string to decode State object.
Returns: State. 
Failure will return a null pointer.
```

**getRound2Msg(state, msg, priv, pubkeys, received_round1_msg)**

```java
It takes a lot of preparation to switch to round2 state(StatePrime). You need the round1 State, the message to sign for it, your own private key, everyone's public key, and everyone else's msgs from the round1.
Returns: StatePrime Pointer. 
Failure will return a null pointer.
```

**getAggSignature(round2_msg)**

```java
To construct a signature requires the status of the round2 msg about the second round of all other signers, and its own R.
Returns: signature String. 
Possible errors are Normal Error and Null Round2 State Pointer.
```

**getAggPublicKey([pubkeys])**
```java
Pass in the public key to generate the aggregated public key
Returns: pubkey String. 
Possible error is Normal Error.
```

### Mast

**generateThresholdPubkey(pubkeys, threshold, network)**

```java
Generate threshold signature addresses by passing in 
all signer public keys and signature thresholds.
network: "mainnet", "signet", "testnet".
Returns: <String>
Return the public key of the threshold-signature address.
Possible error string returned is `Invalid Public Bytes`.
```
**generateControlBlock(pubkeys, threshold, aggPubkey)**
```java
Generate a proof of the aggregated public key by 
passing in the public key and signature threshold of 
all signers and the aggregated public key of everyone 
who performed the signature this time.
Returns: <String>
Return signed proofs for transaction validation.
Possible error string returned is `Invalid Public Bytes`.
```

# Example

The specific usage can be viewed in [ViewController.swift](Musig2Demo/ViewController.swift).This example simulates three people generating aggregated public keys and aggregated signatures firstly. Then including Mast address generation and control block generation.

## Details

## Construct Tx

There are two types of construction transactions, one is the transaction that is spent on constructing a common bench32m address, and the other is the transaction that is spent on constructing the threshold address generated by the following mast (also the address encoded by the bench32m, which cannot be distinguished from the common bench32m address by the naked eye). Constructing a transaction is divided into the following steps:

1. **Pass in the input and output list to construct the initial transaction**. txids and indexes represent input, and must correspond one-to-one. Addresses and amounts represent output, and they must also correspond one-to-one. Note that the output here supports **op_return**, just set amout to 0 and address to the information you want to attach.

   ~~~swift
   let tx = generateRawTx(txids: txids, indexs:indexs, addresses:addresses, amounts: amounts);
   ~~~

2. For each of the above inputs, a corresponding signature is required to be spent, but sighash needs to be generated before signing (that is, a message waiting for signature). When using the **getSighash** function, you need to pay attention to the following: each input cost address corresponding to txid+index must be calculated and signed once by sighash; When the input cost address is normal taproot address, `agg_pubkey` is `""`, `sigversion` is `0` ; When the input cost address is threshold address, `agg_pubkey` is the same as the `agg_pubkey` parameter of `generateControlBlock` in mast, and `sigversion` is `1`;

   input address: normal taproot address

   ~~~swift
   let sighash = getSighash(prev_tx: prev_tx, tx: tx, input_index: 0, agg_pubkey: "", sigversion: 0);
   ~~~

   input address:threshold address

   ~~~swift
   let sighash_1 = getSighash(prev_tx: prev_tx_1, tx: tx_1, input_index: 0, agg_pubkey: pubkey_bc, sigversion: 1);
   ~~~

3. For each input, after calculating the sighash, it needs to be signed. For the normal taproot address, use the `generateSchnorrSignature` function to generate the signature and pass the `message` into the sighash; For the taproot address, the following Musig2 multi-party aggregation signature is required, and the signed message must also be passed to the above sighash

   input address: normal taproot address

   ~~~swift
   let schnorr_signature = generateSchnorrSignature(message: sighash, privkey: private_char);
   ~~~

   input address:threshold address: Use Musig2

4. For each input, after calculating the signature, it needs to be assembled into the initial transaction. Of course, the taproot address also needs to be calculated by mast and passed in `agg_pubkey` and control_block

   input address: normal taproot address

   ~~~swift
   let taproot_tx = buildTaprootTx(tx: tx, signature: schnorr_signature, input_index: 0);
   ~~~

   input address:threshold address: 

   ~~~swift
   let threshold_tx = buildThresholdTx(tx: tx_1, agg_signature: multi_signature, agg_pubkey: pubkey_bc, control: control_1, input_index: 0);

## Musig

- Pass in the phrase to get my privkey

~~~swift
let private0 = getMyPrivkey(phrase: PHRASE0, pd_passphrase: "")
~~~

- Pass in the private key to declare a State pointer and get my pubkey

~~~swift
var round1_state0 = getRound1State()
let pubkey0 = getMyPubkey(priv: private0)
~~~

- Use State pointer to  round1 message.

~~~swift
let round1_msg0 = getRound1Msg(state: round1_state0)
~~~

- Round1 state object serialization

~~~swift
let state_str = encodeRound1State(state: round1_state0);
~~~

- Round1 state object deserialization

~~~swift
round1_state0 = decodeRound1State(round1_state: state_str)
~~~

- Pass the self-generated my_pubkey and round1 message to the other two parties, and the other two parties do the same. In the end, I got the public key and round1 message of the other two parties. Pass in the `getRound2Msg` function to generate my own round2 message. 

~~~swift
let round2_msg0 = getRound2Msg(state: round1_state0, msg: msg, priv: private0, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg1, round1_msg2])
~~~

- Pass the round1 message to the other two parties, and I can finally generate the signature by `getAggSignature`. 

~~~swift
let signature = getAggSignature(round2_msg: [round2_msg0, round2_msg1, round2_msg2])
~~~

- When I obtain the public keys of the other two parties, I can generate the aggregate public key. 

~~~swift
let pubkey = getAggPublicKey(pubkeys: [pubkey0, pubkey1, pubkey2])
~~~

## Mast

- The threshold signature address can be generated by using the threshold and the public key of the all participant.

~~~swift
let threshold_pubkey = generateThresholdPubkey(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2, network: "mainnet");
~~~

- Using the threshold, the public keys of all participants and the aggregation of the public keys can generate a proof.

~~~swift
let control_block = generateControlBlock(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2, agg_pubkey: pubkey01)
~~~





