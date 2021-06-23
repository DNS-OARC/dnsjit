# Example dnsjit module

This module is an example how to create your own modules for dnsjit.

`counter` is a simple filter module that counts objects passed through it.

# Dependencies

To build it will need dnsjit's development files and if you want to run the
test then `dnsjit` itself also.

```
add-apt-repository ppa:dns-oarc/dnsjit-pr
apt-get install dnsjit dnsjit-dev
```

This module also uses two other example modules, input-example and
output-example, so they must also be installed.

## Build

```
sh autogen.sh
mkdir -p build
cd build
../configure
make
make install
```

## Test

```
make test
```
