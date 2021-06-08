```
export CFLAGS="-I$PWD/../../../include"
sh autogen.sh
mkdir -p build
cd build
../configure --prefix=$PWD/root
make
make install
dnsjit test.lua
```

test.lua:
```
package.cpath = package.cpath .. ";./root/lib/?.so"

local zero = require("example.input.zero").new()
print(zero)

local p, c = zero:produce()
print(p, c)

local o = p(c)
print(o)
```
