print[[
.\" Copyright (c) 2018, OARC, Inc.
.\" All rights reserved.
.\"
.\" This file is part of dnsjit.
.\"
.\" dnsjit is free software: you can redistribute it and/or modify
.\" it under the terms of the GNU General Public License as published by
.\" the Free Software Foundation, either version 3 of the License, or
.\" (at your option) any later version.
.\"
.\" dnsjit is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public License
.\" along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
.\"]]

sh_syn = false
sh_desc = false
ss_func = false
doc = {}
funcs = {}
for line in io.lines(arg[1]) do
    if string.match(line, "^[-][-]") then
        table.insert(doc, string.sub(line, 4))
    elseif string.match(line, "^module") then
        if table.maxn(doc) < 2 then
            error("Minimum required module doc missing")
        end
        print(".TH "..doc[1].." 3 \"@PACKAGE_VERSION@\" \"dnsjit\"")
        print(".SH NAME")
        print(doc[1].." \\- "..doc[2])
        n, line = next(doc, 2)
        while line and line > "" do
            if not sh_syn then
                print(".SH SYNOPSIS")
                sh_syn = true
            end
            print(line)
            n, line = next(doc, n)
        end
        n, line = next(doc, n)
        while line and line > "" do
            if not sh_desc then
                print(".SH DESCRIPTION")
                sh_desc = true
            end
            print(line)
            n, line = next(doc, n)
        end
    elseif string.match(line, "^function") then
        if table.maxn(doc) > 0 then
            if not ss_func then
                if not sh_desc then
                    print(".SH DESCRIPTION")
                    sh_desc = true
                end
                print(".SS Functions")
                ss_func = true
            end
            print(".TP")
            print(".BR "..string.sub(line, 10))
            for _, line in pairs(doc) do
                print(line)
            end
        end
    elseif string.match(line, "^return") then
        if table.maxn(doc) > 0 then
            print(".SH SEE ALSO")
            for _, line in pairs(doc) do
                print(".BR "..line)
            end
        end
    else
        doc = {}
    end
end

print[[
.SH AUTHORS
Jerry Lundström, DNS-OARC
.LP
Maintained by DNS-OARC
.LP
.RS
.I https://www.dns-oarc.net/
.RE
.LP
.SH BUGS
For issues and feature requests please use:
.LP
.RS
\fI@PACKAGE_URL@\fP
.RE
.LP
For question and help please use:
.LP
.RS
\fI@PACKAGE_BUGREPORT@\fP
.RE
.LP]]
