const ffi = require('ffi');

const lib = ffi.Library('libmusig_dll', {
  addition: ['uint32', ['uint32', 'uint32']],

  get_my_commit: ['char *', ['string']],
});

function GetMyCommit(priv) {
    const commitPtr = lib.get_my_commit(priv);
    return commitPtr.readCString();
}

console.log(lib.addition(1, 2));
console.log(GetMyCommit("28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"));