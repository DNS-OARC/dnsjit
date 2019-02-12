for line in io.lines("config.h") do
    local n, s = line:match("define SIZEOF_(%S*) (%d+)")
    if n and s then
        if n:match("^PTHREAD") or n:match("^CK_") or n:match("^GNUTLS_") then
            s = math.ceil(s / 8)
            print("#if !defined(SIZEOF_"..n..") || SIZEOF_"..n.." == 0")
            print("#error \""..n.." is undefined or zero\"")
            print("#endif")
            n = n:lower()
            print("typedef struct "..n:sub(1,-3).." { uint64_t a["..s.."]; } "..n..";")
        elseif n:match("^STRUCT") then
            n = n:match("^STRUCT_(%S*)")
            if n == "SOCKADDR_STORAGE" or n == "POLLFD" then
                print("#if !defined(SIZEOF_STRUCT_"..n..") || SIZEOF_STRUCT_"..n.." == 0")
                print("#error \""..n.." is undefined or zero\"")
                print("#endif")
                n = n:lower()
                print("struct "..n.." { uint8_t a["..s.."]; };")
            end
        end
    end
end
