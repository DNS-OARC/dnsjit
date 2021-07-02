# Example stand-alone dnsjit tool

This example consist of two scripts `dnsjit-test-pcap-read` and
`dnsjit-test-throughput`, and shows how you can build, test and install them
using autotools.

They require `input-example` and `output-example` modules to be installed
and that is checked in `dnsjit_modules.lua` which is run during `configure`.

`configure` also checks that `dnsjit` is available and above version 1.0.0
by using `dnsjit_version.lua`.

If you haven't installed `dnsjit` and the modules in a common place (such as
`/usr/local`) then you can use `--with-dnsjit=PATH` to specify where it's
installed (should be same path as given to `dnsjit`'s `--prefix`).

What's not covered here is if you install these tools using `--prefix` in a
custom location that is not known by Lua. Then you need to set `PATH`,
`LUA_PATH` and `LUA_CPATH`, see `src/test` for example and the Lua manual
how these paths work.
