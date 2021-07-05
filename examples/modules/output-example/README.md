# Example dnsjit module

This module is an example how to create your own modules for dnsjit.

`null` is a simple module that does nothing with the objects it receives.

# Dependencies

To build it you will need dnsjit's development files and if you want to run
the test then `dnsjit` itself also.

```
add-apt-repository ppa:dns-oarc/dnsjit-pr
apt-get install dnsjit dnsjit-dev
```

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
