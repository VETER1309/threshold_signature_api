# Overview

This is the js version of musig and musig2 api. Mainly to facilitate the construction of the js version threshold signature wallet.

# Dependencies

~~~json
{
  "dependencies": {
    "musig": "1.6.0",
    "musig2": "1.2.0"
  }
}
~~~

# Api
### Musig

**getMyPrivkey(phrase)**

```
Pass in the phrase to get the private key.
Returns: <String>
Return a 64-byte private key string.
Possible error string returned is `Invalid Phrase`.
```

**getMusig(private)**
```
Pass in the private key string to create the musig pointer for multi-signature.
```

**getMyPubkey(private)**

```
Pass in the private key to get the public key.
Returns: <String>
Return a 32-byte public key string.
Possible error string returned is `Invalid Secret Bytes`.
```

**getMyReveal(musig)**

```
Pass in the musig pointer.
Returns: <String>
Returns a 96-byte reveal string.
Possible error strings returned are `Null Musig` or `Invalid Reveal Bytes`.
```

**encodeRevealStage(musig)**
```
Pass in the musig pointer.
Returns: <String>
Possible error strings returned are `Encode Fail`.
```

**decodeRevealStage(reveal_stage)**
```
Pass in the reveal stage string.
Returns: musig pointer
Possible error strings returned are `Null Musig`.
```

**getMyCosign(musig, [reveals], [pubkeys])**
```
Pass in the musig pointer, the reveals and public-keys of other signers.
Returns: <String>
Returns a 32-byte cosign string.
Possible error strings returned are `Null Musig` or `Invalid Cosign Bytes`.
```

**getAggSignature([reveals], [pubkeys], [cosigns])**
```
Pass in the reveals, public-keys and cosigns of other signers.
Returns: <String>
Returns a 64-byte signature string.
Possible error string returned is `Invalid Signature`.
```

**getAggPublicKey([pubkeys])**
```
Pass in the public-keys to be aggregated.
Returns: <String>
Returns a 32-byte aggregate public-key string.
Possible error strings returned are `Null Musig` or `Invalid Commit Bytes`.
```

### Musig2
**getRound1State()**

```java
To get the State of the first round
Returns: State Pointer If the calculation fails just a null pointer will be returned.
```

**getMyPubkey(private)**

```java
Help to get the PublicKey from privkey
Returns: pubkey string Possible errors are Null KeyPair Pointer and Normal Error.
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

**getRound2Msg(state, msg, privkey, pubkeys, received_round1_msg)**

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

**generateThresholdPubkey(pubkeys, threshold)**
```
Generate threshold signature addresses by passing in 
all signer public keys and signature thresholds.
Returns: <String>
Return the public key of the threshold-signature address.
Possible error string returned is `Invalid Public Bytes`.
```
**generateControlBlock(pubkeys, threshold, aggPubkey)**
```
Generate a proof of the aggregated public key by 
passing in the public key and signature threshold of 
all signers and the aggregated public key of everyone 
who performed the signature this time.
Returns: <String>
Return signed proofs for transaction validation.
Possible error string returned is `Invalid Public Bytes`.
```

# Example

The specific usage can be viewed in [musig.js](src/musig.js) and [musig2.js](src/musig2.js).These examples simulate three people generating aggregated public keys and aggregated signatures.

## Run

~~~
cd MusigDemo
yarn install
~~~

![](https://cdn.jsdelivr.net/gh/AAweidai/PictureBed@master/taproot/16328204386451632820438563.png)

## Detail

### Musig

- Pass in the phrase to generate private key

~~~js
const private0 = getMyPrivkey(phrase0)
~~~

- Pass in the private key to declare a musig pointer and get my pubkey

~~~javascript
const musig0 = getMusig(private0)
const pubkey0 = getMyPubkey(private0)
~~~

- Use musig pointer to  reveal.

~~~javascript
const reveal0 = getMyReveal(musig0)
~~~

- Reveal stage object serialization

~~~javascript
const musig0_reveal_stage = encodeRevealStage(musig0);
~~~

- Reveal stage object deserialization

~~~javascript
const musig0 = decodeRevealStage(musig0_reveal_stage)
~~~

- Pass the self-generated pubkey and reveal to the other two parties, and the other two parties do the same. In the end, I got the public key and reveal of the other two parties. Pass in the `getMyCosign` function to generate my own cosign. **Note that when passing parameters here, pubkey and reveal must correspond one to one**.

~~~javascript
const cosign0 = getMyCosign(musig0, [reveal1, reveal2], [pubkey1, pubkey2])
~~~

- Like commit, pass the cosign and pubkey generated by myself to the other two parties, and I can finally generate the signature by `getAggSignature`. **Note that when passing parameters here, reveal, pubkey and reveal must correspond one to one**.

~~~javascript
const signature = getAggSignature([reveal0, reveal1, reveal2], [cosign0, cosign1, cosign2], [pubkey0, pubkey1, pubkey2])
~~~

- When I obtain the public keys of the other two parties, I can generate the aggregate public key. **Note that the public key here must be in order, and the incoming order of the `getAggSignature` must be consistent.**

~~~javascript
const pubkey = getAggPublicKey([pubkey0, pubkey1, pubkey2])
~~~

### Musig2

- First pass in the private key to declare a State pointer and get my pubkey

~~~javascript
let round1StateA = getRound1State()
let pubkeyA = getMyPubkey(privateA)
~~~

- Use State pointer to  round1 message.

~~~javascript
let round1MsgA = getRound1Msg(round1StateA)
~~~

- Round1 state object serialization

~~~javascript
let encodedRound1StateA = encodeRound1State(round1StateA);
~~~

- Round1 state object deserialization

~~~javascript
round1StateA = decodeRound1State(encodedRound1StateA)
~~~

- Pass the self-generated my_pubkey and round1 message to the other two parties, and the other two parties do the same. In the end, I got the public key and round1 message of the other two parties. Pass in the `getRound2Msg` function to generate my own round2 message. 

~~~javascript
let round2MsgA = getRound2Msg(round1StateA, msg, privkeyA, [pubkeyA, pubkeyB, pubkeyC], [round1MsgB, round1MsgC])
~~~

- Pass the round1 message to the other two parties, and I can finally generate the signature by `getAggSignature`. 

~~~javascript
let signature = getAggSignature([round2MsgA, round2MsgB, round2MsgC])
~~~

- When I obtain the public keys of the other two parties, I can generate the aggregate public key. 

~~~javascript
let pubkey = getAggPublicKey([round1MsgA, round1MsgB, round1MsgC])
~~~

### Mast

- The threshold signature address can be generated by using the threshold and the public key of the all participant.

~~~javascript
const threshold_pubkey = generateThresholdPubkey([pubkeya, pubkeyb, pubkeyc], 2);
~~~

- Using the threshold, the public keys of all participants and the aggregation of the public keys can generate a proof.

~~~javascript
const control_block = generateControlBlock( [pubkeya, pubkeyb, pubkeyc], 2, pubkeyab)
~~~



