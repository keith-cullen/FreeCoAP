#!/bin/bash

ROOTFS="/home/keith/quark/rootfs"
SDK="/opt/iot-devkit/1.7.2"
CC="${SDK}/sysroots/x86_64-pokysdk-linux/usr/bin/i586-poky-linux/i586-poky-linux-gcc"
EXTRA_CFLAGS="-m32 -march=i586 -O2 -pipe -g -feliminate-unused-debug-types"
LD="${SDK}/sysroots/x86_64-pokysdk-linux/usr/bin/i586-poky-linux/i586-poky-linux-ld"
EXTRA_LDFLAGS=""
EXTRA_LIBS=""

make "ROOTFS=${ROOTFS}" "CC=${CC}" "EXTRA_CFLAGS=${EXTRA_CFLAGS}" "LD=${CC}" "EXTRA_LDFLAGS=${EXTRA_LDFLAGS}" "EXTRA_LIBS=${EXTRA_LIBS}"
