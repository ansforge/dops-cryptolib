### BUILD LINUX Library (static or dynamic) ###
#!/bin/bash

# Don't include the current LIBPATH in the loader section of module generated
export LIBPATH=/usr/lib:/lib
export DLL_VER=0
export FULL_VER=1.0.4

if test "$1" = "d"
then
	COMPILE_MODE="debug"
fi

if test "$1" = "r"
then
	COMPILE_MODE="release"
fi

LINK_MODE=exe


if test "$LINK_MODE" = ""
then
	if test "$COMPILE_MODE" = ""
	then
		echo "build [d|r] [clean]"
		return 1
	fi
fi

#######################################

export sysconfdir=/etc
VER_COMMON="-D UNIX_LUX -D HAVE_CONFIG_H -D MODULE_IAS -D ENABLE_OPENSSL -D ENABLE_GALSS -D OPENSCPKCS11_EXPORTS -D PKCS11_THREAD_LOCKING -D ENABLE_PCSC -D _MULTI_THREADED"
if test $COMPILE_MODE = "debug"
then
	export DEBUG="-g -D _DEBUG" 
	export RELEASE=
	export VER="${DEBUG} ${VER_COMMON}"
	export REPVER="debug64"
	export REPVER_LIBS="lib_linux64/release"
else
	export DEBUG=
	export RELEASE=
	export VER="${RELEASE} -O2  ${VER_COMMON}"
	export REPVER="release64"
	export REPVER_LIBS="lib_linux64/release"
fi

export REPVER_OPENSSL=${REPVER_LIBS}


# Dynamic link
export REPVER=${REPVER}
export REPVER_LIBS=${REPVER_LIBS}
export CFLAGS="-fPIC ${VER} -c -Wall"
export LDFLAGS="-shared -Wl"


export LDFLAGS_TST=
export CFLAGS_TST="-m64 -fPIC -c -Wall ${VER} -D WITH_OPENSSL -D NEW_VERSION_PROD"
export LIBS_TST=-lstdc++

# Creation du répertoire s'il n'existe pas
if [ ! -d ./${REPVER} ]
then
	mkdir ./${REPVER}
fi

PROJ=pkcs11_test

dos2unix ${PROJ}.mak

if test "$2" = "clean"
then
  make -f ${PROJ}.mak cleanup
fi

# make -f ${PROJ}.mak ${LINK_MODE}
DATE=`date`
echo "*******************************************************************************" > ${REPVER}/build.lst
echo "${PROJ} ${REPVER} ${LINK_MODE}          ${DATE}" >> ${REPVER}/build.lst
echo "-------------------------------------------------------------------------------" >> ${REPVER}/build.lst
echo "*******************************************************************************" > ${REPVER}/build.err
echo "${PROJ} ${REPVER} ${LINK_MODE}          ${DATE}" >> ${REPVER}/build.err
echo "-------------------------------------------------------------------------------" >> ${REPVER}/build.err
make -f ./${PROJ}.mak ${LINK_MODE} 2>>${REPVER}/build.err
if test $? = 0
then
	echo "\b"
	echo "OK    (Verify also: ${REPVER}/build.err)"
	echo "OK    (Verify also: ${REPVER}/build.err)" >> ${REPVER}/build.lst
#	cd ./${REPVER}
#        ln -sv ${PWD}/libcps3_pkcs11_lux.so.${FULL_VER} libcps3_pkcs11_lux.so
#        cd ..
else
	echo "ERROR (See: ${REPVER}/build.err)"
	echo "ERROR (See: ${REPVER}/build.err)"  >> ${REPVER}/build.lst
fi
echo "*******************************************************************************" >> ${REPVER}/build.lst
echo "*******************************************************************************" >> ${REPVER}/build.err

