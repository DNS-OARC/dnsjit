for line in io.lines("config.h") do
    local n,s = line:match("define SIZEOF_(PTHREAD%S*)_T (%d+)")
    if n and s then
        s = math.ceil(s / 8)
        n = n:lower()
        print("typedef struct "..n.." { uint64_t a["..s.."]; } "..n.."_t;")
    end
end
