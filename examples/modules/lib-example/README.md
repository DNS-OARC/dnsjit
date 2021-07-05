# Example dnsjit module

This module is an example how to create your own modules for dnsjit.

`duration` is a simple Lua module that tells you the duration between
two `core.timespec`.

# Dependencies

To build this you will need `dnsjit` installed.

```
add-apt-repository ppa:dns-oarc/dnsjit-pr
apt-get install dnsjit
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
