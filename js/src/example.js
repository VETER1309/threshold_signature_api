const ffi = require('ffi');

const lib = ffi.Library('libmusig_dll', {
  addition: ['uint32', ['uint32', 'uint32']],
});

console.log(lib.addition(1, 2));
