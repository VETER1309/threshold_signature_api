# Overview

This is an example of using musig as an aar package. Some help for building a threshold signature wallet for Android.

# Dependencies

Step 1. Add the JitPack repository to your build file

```
allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
```

Step 2. Add the dependency
```
dependencies {
	        implementation 'com.github.hacpy:musig:1.0.2'
	}
```

Step 3. Import musig
```
import com.example.musig.Musig;
```


## Details

- First pass in the private key to declare a Musig instance

~~~java
Musig musig0 = new Musig(private1);
~~~

- Use Musig instance to get my own public key and commit.

~~~java
String pubkey0 = musig0.getMyPubkey();
String commit0 = musig0.getMyCommit();
~~~

- Pass the self-generated pubkey and commit to the other two parties, and the other two parties do the same. In the end, I got the public key and commit of the other two parties. Pass in the `getMyReveal` function to generate my own reveal. **Note that when passing parameters here, pubkey and commit must correspond one to one**.

~~~java
String reveal0 = musig0.getMyReveal(new String[]{commit1, commit2},
                new String[]{pubkey1, pubkey2});
~~~

- Like commit, pass the reveal and pubkey generated by myself to the other two parties, and I can finally generate the cosign by `getMyCosign`. The pubkey is repeatedly passed here to identify reveal. **Note that when passing parameters here, pubkey and reveal must correspond one to one**.

~~~java
String cosign0 = musig0.getMyCosign(new String[]{reveal1, reveal2},
                new String[]{pubkey1, pubkey2});
~~~

- Like commit, pass the cosign and pubkey generated by myself to the other two parties, and I can finally generate the signature by `getAggSignature`. **Note that when passing parameters here, reveal, pubkey and reveal must correspond one to one**.

~~~java
String signature = musig0.getAggSignature(new String[]{reveal0, reveal1, reveal2},
                new String[]{cosign0, cosign1, cosign2},
                new String[]{pubkey0, pubkey1, pubkey2});
~~~

- When I obtain the public keys of the other two parties, I can generate the aggregate public key. **Note that the public key here must be in order, and the incoming order of the `getAggSignature` must be consistent.**

~~~java
String pubkey = musig0.getAggPublicKey(new String[]{pubkey0, pubkey1, pubkey2});
~~~


