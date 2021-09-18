# Overview

This is the js version of musig api. Mainly to facilitate the construction of the js version threshold signature wallet.



# Install

## install ffi

In order to install ffi first need to install node-gyp.

### node-gyp

~~~
npm install node-gyp -g
~~~

### ffi

 If the direct installation fails, you can switch to node-v10 and install again

~~~
npm install ffi -S
~~~



# Compile

## Compile musig-dll

~~~
cargo build
~~~



# Run

Run example

~~~
npm run example
or
yarn example
~~~

