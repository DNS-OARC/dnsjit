AC_PREREQ(2.61)
AC_INIT([stand-alone-tool], [1.0.0],,)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/example.lua])

# Checks for dnsjit.
AC_PATH_PROG([DNSJIT],[dnsjit])
AS_IF([test "x$ac_cv_path_DNSJIT" = "x"], [
  AC_MSG_ERROR([dnsjit was not found])
])
AC_MSG_CHECKING([for dnsjit >= 1.0.0])
AS_IF(["$DNSJIT" "$srcdir/dnsjit_version.lua" 1 0 0 2>/dev/null], [
  AC_MSG_RESULT([yes])
], [
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([dnsjit version does not meet the requirements])
])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
