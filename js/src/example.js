const ffi = require('ffi');

const lib = ffi.Library('libmusig_dll', {
  addition: ['uint32', ['uint32', 'uint32']],
  get_my_commit: ['char *', ['string']],
});

function GetMyCommit(priv) {
    const commitPtr = lib.get_my_commit(priv);
    return commitPtr.readCString();
}


// Test Data:

// private 0: 54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2
// public 0: e283f9f07f5bae9a2ea1b4cfea313b3b5e29e0cac2dec126e788f0bf811ff82b
// private 1: db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38
// public 1: 40c01b70fe175c6db4f01d3ef5b4f96b5bc31f33d22b0a9b84f3ab75fc7e6c72
// private 2: 330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59
// public 2: dcb27a4ddd6f52216b294c8392d53b85099bbe9f7235914364334ee8f2ea707e
// ------- commit stage -------
// commit 0 --> 8d4d84f620237a9e73f1589dd2c6ae9b
// commit 1 --> ba8ab542d3d9c0f9fa9c332552c6a98b
// commit 2 --> 171e4798c3b90f85a938f29bef0f51ff
// ------- reveal stage -------
// reveal 0 --> 0aa37ab268d4a92de4200ebc4004fa79394b7cd6322f27dafb3bc1bc5f7b0945c6ebc679112d045ea04acbbd9c31eeedf82f34e8b151dd586e7c14bfbea82a07c89596b555de63f0ea7a0cf211f2704d00c965f1b6b1fc7dc45e901367c8b141
// reveal 1 --> febece55a4d9d303ba38fcb3b139ca56fce97d0d22c3dd0867dbba85caff663f50de350612900be44cc82fe13c7f37fc058a6bb6ce9556b2ecb245eed89c635a5aed6c8ac5621d97e58817254b337ffa08ff67bbe944b5d46f9e1d5fefc65606
// reveal 2 --> 841dad57f34fb176cf14a7d847838c812da1ca0af24a7b94bf92395510228f0efe4adf4b9c1b9dbe5dcffa0d8e75e7675bec4e602bd822cf4d0de8115f9a2f0f04cf2c3aa7fd415ef95db548e9fa8aa57f54cf45fab68f50dc4b087b39b27b1f
// ------- cosign stage -------
// reveal 0 --> 25bb22295ccfe3b46a1ecdf8e44ac8d06540c5bacc108d232bc03d85c721910e
// reveal 1 --> 04a659c1e6f592ae6be84e756ee17172eeb7034ee12bbc5bd71fef0cd3055005
// reveal 2 --> f0fcdb11526bea05f122386f81f7186d1a611ef13de8eb07c24e76644d3cd900

// signature: fcfb8734e452a390a92d9805579e09033b60ee93022e9aa02b14e2b7cb7811402c8a629f7acd4e11f18c5c3af629749b6e59e7f9eb243587c42ea3f6e763ba84


console.log(lib.addition(1, 2));
console.log(GetMyCommit("54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"));