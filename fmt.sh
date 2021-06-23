#!/bin/sh
# Copyright (c) 2018-2021, OARC, Inc.
# All rights reserved.
#
# This file is part of dnsjit.
#
# dnsjit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# dnsjit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

clang-format \
    -style=file \
    -i \
    src/*.c \
    `find src/core src/input src/filter src/output src/lib examples/modules -name '*.c'` \
    `find src/core src/input src/filter src/output src/lib -name '*.h'` \
    `find src/core src/input src/filter src/output src/lib -name '*.hh'`
