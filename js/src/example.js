const ffi = require('ffi');

const lib = ffi.Library('libmusig_dll', {
  get_musig: ['pointer', ['string']],
  get_my_commit: ['char *', ['pointer']],
});

function GetMyCommit(musig) {
    const commitPtr = lib.get_my_commit(musig);
    return commitPtr.readCString();
}

const musig = lib.get_musig("54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2");
console.log(GetMyCommit(musig));
