-- Copyright (c) 2018-2021, OARC, Inc.
-- All rights reserved.
--
-- This file is part of dnsjit.
--
-- dnsjit is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- dnsjit is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

-- dnsjit.core.object.dns.label
-- Container of a DNS label
--
-- The object that describes a DNS label.
-- To extract a domain name label first check that
-- .I have_dn
-- is set, then use
-- .I "offset + 1"
-- to indicate where in the payload the label start and
-- .I length
-- for how many bytes long it is.
-- .SS Attributes
-- .TP
-- is_end
-- .TP
-- have_length
-- Set if there is a length.
-- .TP
-- have_offset
-- Set if there is an offset.
-- .TP
-- have_extension_bits
-- Set if there is extension bits.
-- .TP
-- have_dn
-- Set if the label contained a domain name.
-- .TP
-- extension_bits
-- The extension bits.
-- .TP
-- length
-- The length of the domain name.
-- .TP
-- offset
-- If
-- .I have_dn
-- is set then this contains the offset within the payload to where this label
-- start otherwise it contains the offset to another label.
module(...,package.seeall)

require("dnsjit.core.object.dns_h")
local ffi = require("ffi")

local Label = {}

-- Create a new array of labels.
function Label.new(size)
    return ffi.new("core_object_dns_label_t[?]", size)
end

-- Returns labels as a string and an offset to the next label.
-- The string may be nil if the first label was an offset.
-- The offset may be nil if the last label was an extension bits or end marker.
function Label.tostring(dns, labels, num_labels, offset_labels)
    if offset_labels == nil then
        offset_labels = 0
    end
    local dn
    for n = 1, tonumber(num_labels) do
        local label = labels[n - 1 + offset_labels]

        if label.have_dn == 1 then
            if dn == nil then
                dn = ""
            end
            dn = dn .. ffi.string(dns.payload + label.offset + 1, label.length) .. "."
        elseif label.have_offset == 1 then
            return dn, label.offset
        else
            return dn, nil
        end
    end
    return dn, nil
end

-- Returns labels as a string which also includes a textual notation of the
-- offset in the form of
-- .IR "<offset>label" .
function Label.tooffstr(dns, labels, num_labels, offset_labels)
    if offset_labels == nil then
        offset_labels = 0
    end
    local dn = ""
    for n = 1, tonumber(num_labels) do
        local label = labels[n - 1 + offset_labels]

        if label.have_dn == 1 then
            dn = dn .. "<" .. tonumber(label.offset) .. ">" .. ffi.string(dns.payload + label.offset + 1, label.length) .. "."
        elseif label.have_offset == 1 then
            dn = dn .. "<" .. tonumber(label.offset) .. ">"
            break
        else
            break
        end
    end
    return dn
end

-- dnsjit.core.object.dns (3)
return Label
