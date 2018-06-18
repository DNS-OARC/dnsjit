#!/bin/sh

includes="/usr/include/errno.h"
if [ -f /usr/include/sys/errno.h ]; then
  includes="$includes /usr/include/sys/errno.h"
fi
if [ -f /usr/include/asm-generic/errno.h ]; then
  includes="$includes /usr/include/asm-generic/errno.h"
fi
if [ -f /usr/include/asm-generic/errno-base.h ]; then
  includes="$includes /usr/include/asm-generic/errno-base.h"
fi

echo 'const char* core_log_errstr(int err)
{
    switch (err) {'

egrep -Eh '^#define[	 ]+E\w+[	 ]+[0-9]+' $includes |
  grep -v ELAST |
  awk '{print $2}' |
  sort -u |
  awk '{print "#ifdef " $1 "\n    case " $1 ":\n        return \"" $1 "\";\n#endif"}'

echo '    default:
        break;
    }
    return "UNKNOWN";
}'
