AC_INIT([freecoap], [0.5], [keithcullen77@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
AM_PROG_AR
AC_CHECK_LIB([gnutls], [gnutls_check_version], [], [AC_MSG_ERROR([libgnutls not found])])
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
