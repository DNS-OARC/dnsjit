if arg[2] > "" then
    package.path = package.path .. ";" .. arg[2] .. "/share/lua/5.1/?.lua"
    package.cpath = package.cpath .. ";" .. arg[2] .. "/lib/lua/5.1/?.so"
end
local ok = pcall(function()
    require("example.input.zero")
    require("example.output.null")
end)
if ok == true then
    os.exit(0)
end
os.exit(1)
