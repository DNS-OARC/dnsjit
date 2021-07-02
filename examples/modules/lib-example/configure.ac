AC_PREREQ(2.61)
AC_INIT([example-lib-duration], [1.0.0],,)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/lib/duration.lua])

# Checks for dnsjit.
DNSJIT_ROOT=
AC_ARG_WITH([dnsjit], [AS_HELP_STRING([--with-dnsjit=PATH], [Use PATH when checking for dnsjit binaries])], [
  AC_PATH_PROG([DNSJIT],[dnsjit],,[$withval/bin])
  DNSJIT_ROOT="$withval"
], [
  AC_PATH_PROG([DNSJIT],[dnsjit])
])
AC_SUBST([DNSJIT_ROOT])
AS_IF([test "x$ac_cv_path_DNSJIT" = "x"], [
  AC_MSG_ERROR([dnsjit was not found])
])
AC_MSG_CHECKING([for dnsjit >= 1.0.0])
AS_IF(["$DNSJIT" "$srcdir/dnsjit_version.lua" 1 0 0], [
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
