-- Copyright (c) 2018, OARC, Inc.
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

-- dnsjit.core
-- Core modules for dnsjit
--
-- Core modules for handling things like logging, DNS messages and
-- receiver/receive functionality.
-- .SS Global Variables
-- The following global variables exists in
-- .IR dnsjit .
-- .TP
-- .B arg
-- A table with the arguments given on the command line, the first will be
-- the path to the
-- .I dnsjit
-- binary, second will be the path to the
-- .IR script .
module(...,package.seeall)

error("This should not be included, only here for documentation generation")

-- dnsjit.core.chelpers (3),
-- dnsjit.core.log (3),
-- dnsjit.core.mutex (3),
-- dnsjit.core.object (3),
-- dnsjit.core.receiver (3),
-- dnsjit.core.timespec (3),
-- dnsjit.core.tracking (3)
return
