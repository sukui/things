
local DELTA = 0x9E3779B9

local function long2str(v,w)
    local len = #v
    local n = len << 2
    if w then
        local m = v[len]
        n = n - 4
        if ((m < n-3) or (m >n)) then
            return false
        end
        n = m
    end
    local s  = {}
    for i = 1,len do
        s[i] = string.pack("<I4",v[i])
    end
    if w then
        return string.sub(table.concat(s),0,n)
    else
        return table.concat(s)
    end
end

local function str2long(s,w)
    local result = {}
    local newStr = s..string.rep("\0",(4-string.len(s)%4) & 3)
    local len = string.len(newStr)
    for i=1,len/4 do
        local ss = string.unpack("<I4",string.sub(newStr,(i-1)*4+1,(i-1)*4+4))
        table.insert(result,ss)
    end
    if w then
        table.insert(result,#result+1,string.len(s))
    end
    return result
end

local function int32(n)
    return (n & 0xffffffff)
end

local function mx(sum,y,z,p,e,k)
    return (((z >> 5 & 0x07ffffff) ~ y << 2) + ((y >> 3 & 0x1fffffff) ~ z << 4)) ~ ((sum ~ y) + (k[(p & 3 ~ e)+1] ~ z))
end

local function fixk(k)
    local len = #k
    if len < 4 then
        for i = len+1,4 do 
            k[i] = 0;
        end
    end
    return k;
end

function encrypt(str,key)
    if not str then
        return ""
    end
    local v = str2long(str,true)
    local k = fixk(str2long((key or ""),false))
    local n = #v
    local z = v[n]
    local q = math.floor(6+52/(n))
    local sum = 0
    while 0 < q do
        q = q - 1
        sum = int32(sum+DELTA)
        local e = sum >> 2 & 3
        local p
        local y
        for i = 0,n-2 do
            p = i+1;
            y = v[p+1]
            v[p] = int32(v[p]+mx(sum,y,z,i,e,k))
            z = v[p]
        end
        y = v[1];
        v[n] = int32(v[n]+mx(sum,y,z,p,e,k))
        z = v[n]
    end
    return long2str(v,false)
end

function decrypt(str,key)
    if not str then
        return ""
    end
    local v = str2long(str,false)
    local k = fixk(str2long((key or ""),false))
    local n = #v
    local y = v[1]
    local q = math.floor(6+52/(n))
    local sum = int32(q*DELTA)
    while sum ~= 0 do
        local e = sum >> 2 & 3
        local p = n
        local z
        while p>1 do
            z = v[p-1];
            v[p] = int32(v[p]-mx(sum,y,z,p-1,e,k))
            y = v[p]
            p = p-1
        end
        z = v[n]
        v[1] = int32(v[1]-mx(sum,y,z,p-1,e,k))
        y = v[1];
        sum = int32(sum-DELTA)
    end
    return long2str(v,true)
end


local test = encrypt("嘿嘿嘿",'我是密码')
print(decrypt(test,"我是密码"))



local test = "\x55\x09\x11\x44\x00\xAA";

print(string.byte(test,1,4))
print(string.format("%s",test),string.char(255));
