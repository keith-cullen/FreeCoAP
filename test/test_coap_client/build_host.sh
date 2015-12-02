#!/bin/bash

DTLS_EN="dtls=n"

for i in $@; do
  case "$i" in
    dtls)
    DTLS_EN="dtls=y"
    ;;
  esac
done

ROOTFS=""
CC="gcc"
EXTRA_CFLAGS=""
LD="ld"
EXTRA_LDFLAGS=""
EXTRA_LIBS=""

make "${DTLS_EN}" "ROOTFS=${ROOTFS}" "CC=${CC}" "EXTRA_CFLAGS=${EXTRA_CFLAGS}" "LD=${CC}" "EXTRA_LDFLAGS=${EXTRA_LDFLAGS}" "EXTRA_LIBS=${EXTRA_LIBS}"
