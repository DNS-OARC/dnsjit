AC_PREREQ(2.61)
AC_INIT([example-filter-counter], [1.0.0],,)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])

# Check for dnsjit development files
AC_ARG_WITH([dnsjit], [AS_HELP_STRING([--with-dnsjit=PATH], [Use PATH when checking for dnsjit development files])], [
  AS_VAR_APPEND(CFLAGS, [" -I$withval/include"])
])
AC_CHECK_HEADER([dnsjit/version.h],, [AC_MSG_ERROR([dnsjit development headers not found])])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
