#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Coffee forensics tool], [0.1], [jens.p.sandvik@ntnu.no])
AC_CONFIG_SRCDIR([src/coffee_file_extract.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_CPP
AC_PROG_MKDIR_P

# Checks for libraries.
AC_SEARCH_LIBS([ceil], [m])
AC_SEARCH_LIBS([crypto_hash_sha256], [sodium])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sodium.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero memset mkdir munmap])

AC_CONFIG_FILES([Makefile
		src/Makefile])
AC_OUTPUT
