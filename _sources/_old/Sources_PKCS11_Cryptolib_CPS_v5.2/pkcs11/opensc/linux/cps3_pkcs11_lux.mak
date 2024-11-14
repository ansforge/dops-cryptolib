CC=gcc
AR=ar

PROJ=cps3_pkcs11_lux

SRC_PATH=../src
SRC_PATH_SCCONF=$(SRC_PATH)/scconf
SRC_PATH_LIBOPENSC=$(SRC_PATH)/libopensc
SRC_PATH_COMMON=$(SRC_PATH)/common
SRC_PATH_PKCS11=$(SRC_PATH)/pkcs11
SRC_PATH_SYSTEM=../unix/src

INCLUDES=-I../unix/src \
	-I${SRC_PATH_COMMON} \
	-I${SRC_PATH_PKCS11} \
	-I$(SRC_PATH) \
	-I$(SRC_PATH_LIBOPENSC) \
	-I../../openssl/include_linux \
	-I../../openssl/include \
	-I../../../common \
	-I/usr/include/PCSC
	

LIBDIR=-L./$(REPVER) \
	-L../../openssl/lib_linux/release \
	-L../../openssl/lib_linux64/release
	
	

################################################################################

OBJFILES=./$(REPVER)/parse.o \
	./$(REPVER)/scconf.o \
	./$(REPVER)/sclex.o \
	./$(REPVER)/apdu.o \
	./$(REPVER)/asn1.o \
        ./$(REPVER)/card-cps.o \
	./$(REPVER)/card-cps3.o \
	./$(REPVER)/card-cps4.o \
	./$(REPVER)/card.o \
	./$(REPVER)/ctx.o \
	./$(REPVER)/dir.o \
	./$(REPVER)/errors.o \
	./$(REPVER)/iso7816.o \
	./$(REPVER)/log.o \
	./$(REPVER)/padding.o \
	./$(REPVER)/pkcs15-algo.o \
	./$(REPVER)/pkcs15-cache.o \
	./$(REPVER)/pkcs15-cert.o \
	./$(REPVER)/pkcs15-data.o \
	./$(REPVER)/pkcs15-pin.o \
	./$(REPVER)/pkcs15-prkey.o \
	./$(REPVER)/pkcs15-pubkey.o \
	./$(REPVER)/pkcs15-sec.o \
	./$(REPVER)/pkcs15-syn.o \
	./$(REPVER)/pkcs15.o \
	./$(REPVER)/reader-galss.o \
	./$(REPVER)/reader-pcsc.o \
	./$(REPVER)/sc.o \
	./$(REPVER)/sec.o \
	./$(REPVER)/compat_strlcpy.o \
	./$(REPVER)/debug.o \
	./$(REPVER)/framework-pkcs15.o \
	./$(REPVER)/mechanism.o \
	./$(REPVER)/misc.o \
	./$(REPVER)/openssl.o \
	./$(REPVER)/pkcs11-global.o \
	./$(REPVER)/pkcs11-object.o \
	./$(REPVER)/pkcs11-session.o \
	./$(REPVER)/secretkey.o \
	./$(REPVER)/slot.o \
	./$(REPVER)/encdec.o \
	./$(REPVER)/pkcs11-display.o \
	./$(REPVER)/pkcs11-spy.o \
	./$(REPVER)/system.o \
  ./$(REPVER)/sys_config.o
	

dll:	./$(REPVER)/lib$(PROJ).so.$(FULL_VER)

./$(REPVER)/lib$(PROJ).so.$(FULL_VER):    $(OBJFILES)
	$(CC) $(LDFLAGS),--version-script,symbols.exp,-soname,lib$(PROJ).so.$(DLL_VER) -o ./$(REPVER)/lib$(PROJ).so $(OBJFILES) $(LIBDIR) -lcrypto.0.9.8n -ldl -lpthread -lc

		

cleanup :
	rm -f $(PATH_TEST)/$(REPVER)/*.o
	rm -f $(REPVER)/*.o
	rm -f $(REPVER)/cpgeslux
	rm -f $(REPVER)/build.lst
	rm -f $(REPVER)/build.err

################################################################################

./$(REPVER)/parse.o :  $(SRC_PATH_SCCONF)/parse.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_SCCONF)/parse.c -o ./$(REPVER)/parse.o

	
################################################################################

./$(REPVER)/scconf.o :  $(SRC_PATH_SCCONF)/scconf.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_SCCONF)/scconf.c -o ./$(REPVER)/scconf.o

	
################################################################################

./$(REPVER)/sclex.o :  $(SRC_PATH_SCCONF)/sclex.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_SCCONF)/sclex.c -o ./$(REPVER)/sclex.o


################################################################################

./$(REPVER)/apdu.o :  $(SRC_PATH_LIBOPENSC)/apdu.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/apdu.c -o ./$(REPVER)/apdu.o

################################################################################

./$(REPVER)/asn1.o :  $(SRC_PATH_LIBOPENSC)/asn1.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/asn1.c -o ./$(REPVER)/asn1.o

################################################################################

./$(REPVER)/card-cps.o :  $(SRC_PATH_LIBOPENSC)/card-cps.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/card-cps.c -o ./$(REPVER)/card-cps.o

################################################################################

./$(REPVER)/card-cps3.o :  $(SRC_PATH_LIBOPENSC)/card-cps3.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/card-cps3.c -o ./$(REPVER)/card-cps3.o
	
################################################################################

./$(REPVER)/card-cps4.o :  $(SRC_PATH_LIBOPENSC)/card-cps4.c
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/card-cps4.c -o ./$(REPVER)/card-cps4.o

################################################################################

./$(REPVER)/card.o :  $(SRC_PATH_LIBOPENSC)/card.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/card.c -o ./$(REPVER)/card.o

################################################################################

./$(REPVER)/ctx.o :  $(SRC_PATH_LIBOPENSC)/ctx.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/ctx.c -o ./$(REPVER)/ctx.o

################################################################################

./$(REPVER)/dir.o :  $(SRC_PATH_LIBOPENSC)/dir.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/dir.c -o ./$(REPVER)/dir.o

################################################################################

./$(REPVER)/errors.o :  $(SRC_PATH_LIBOPENSC)/errors.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/errors.c -o ./$(REPVER)/errors.o

################################################################################

./$(REPVER)/iso7816.o :  $(SRC_PATH_LIBOPENSC)/iso7816.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/iso7816.c -o ./$(REPVER)/iso7816.o

################################################################################

./$(REPVER)/log.o :  $(SRC_PATH_LIBOPENSC)/log.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/log.c -o ./$(REPVER)/log.o

################################################################################

./$(REPVER)/padding.o :  $(SRC_PATH_LIBOPENSC)/padding.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/padding.c -o ./$(REPVER)/padding.o

################################################################################

./$(REPVER)/pkcs15-algo.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-algo.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-algo.c -o ./$(REPVER)/pkcs15-algo.o

################################################################################

./$(REPVER)/pkcs15-cache.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-cache.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-cache.c -o ./$(REPVER)/pkcs15-cache.o

################################################################################

./$(REPVER)/pkcs15-cert.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-cert.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-cert.c -o ./$(REPVER)/pkcs15-cert.o

################################################################################

./$(REPVER)/pkcs15-data.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-data.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-data.c -o ./$(REPVER)/pkcs15-data.o

################################################################################

./$(REPVER)/pkcs15-pin.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-pin.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-pin.c -o ./$(REPVER)/pkcs15-pin.o

################################################################################

./$(REPVER)/pkcs15-prkey.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-prkey.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-prkey.c -o ./$(REPVER)/pkcs15-prkey.o

################################################################################

./$(REPVER)/pkcs15-pubkey.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-pubkey.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-pubkey.c -o ./$(REPVER)/pkcs15-pubkey.o

################################################################################

./$(REPVER)/pkcs15-sec.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-sec.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-sec.c -o ./$(REPVER)/pkcs15-sec.o

################################################################################

./$(REPVER)/pkcs15-syn.o :  $(SRC_PATH_LIBOPENSC)/pkcs15-syn.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15-syn.c -o ./$(REPVER)/pkcs15-syn.o

################################################################################

./$(REPVER)/pkcs15.o :  $(SRC_PATH_LIBOPENSC)/pkcs15.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/pkcs15.c -o ./$(REPVER)/pkcs15.o

################################################################################

./$(REPVER)/reader-galss.o :  $(SRC_PATH_LIBOPENSC)/reader-galss.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/reader-galss.c -o ./$(REPVER)/reader-galss.o

################################################################################

./$(REPVER)/reader-pcsc.o :  $(SRC_PATH_LIBOPENSC)/reader-pcsc.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/reader-pcsc.c -o ./$(REPVER)/reader-pcsc.o

################################################################################

./$(REPVER)/sc.o :  $(SRC_PATH_LIBOPENSC)/sc.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/sc.c -o ./$(REPVER)/sc.o

################################################################################

./$(REPVER)/sec.o :  $(SRC_PATH_LIBOPENSC)/sec.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/sec.c -o ./$(REPVER)/sec.o

################################################################################

./$(REPVER)/encdec.o : $(SRC_PATH_LIBOPENSC)/encdec.c
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_LIBOPENSC)/encdec.c -o ./$(REPVER)/encdec.o

################################################################################

./$(REPVER)/compat_strlcpy.o :  $(SRC_PATH_COMMON)/compat_strlcpy.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_COMMON)/compat_strlcpy.c -o ./$(REPVER)/compat_strlcpy.o

################################################################################

./$(REPVER)/debug.o :  $(SRC_PATH_PKCS11)/debug.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/debug.c -o ./$(REPVER)/debug.o

################################################################################

./$(REPVER)/framework-pkcs15.o :  $(SRC_PATH_PKCS11)/framework-pkcs15.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/framework-pkcs15.c -o ./$(REPVER)/framework-pkcs15.o

################################################################################

./$(REPVER)/mechanism.o :  $(SRC_PATH_PKCS11)/mechanism.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/mechanism.c -o ./$(REPVER)/mechanism.o

################################################################################

./$(REPVER)/misc.o :  $(SRC_PATH_PKCS11)/misc.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/misc.c -o ./$(REPVER)/misc.o

################################################################################

./$(REPVER)/openssl.o :  $(SRC_PATH_PKCS11)/openssl.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/openssl.c -o ./$(REPVER)/openssl.o

################################################################################

./$(REPVER)/pkcs11-global.o :  $(SRC_PATH_PKCS11)/pkcs11-global.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/pkcs11-global.c -o ./$(REPVER)/pkcs11-global.o

################################################################################

./$(REPVER)/pkcs11-object.o :  $(SRC_PATH_PKCS11)/pkcs11-object.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/pkcs11-object.c -o ./$(REPVER)/pkcs11-object.o

################################################################################

./$(REPVER)/pkcs11-session.o :  $(SRC_PATH_PKCS11)/pkcs11-session.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/pkcs11-session.c -o ./$(REPVER)/pkcs11-session.o

################################################################################

./$(REPVER)/secretkey.o :  $(SRC_PATH_PKCS11)/secretkey.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/secretkey.c -o ./$(REPVER)/secretkey.o

################################################################################

./$(REPVER)/slot.o :  $(SRC_PATH_PKCS11)/slot.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/slot.c -o ./$(REPVER)/slot.o
	
################################################################################

./$(REPVER)/pkcs11-display.o :  $(SRC_PATH_PKCS11)/pkcs11-display.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/pkcs11-display.c -o ./$(REPVER)/pkcs11-display.o

################################################################################

./$(REPVER)/pkcs11-spy.o :  $(SRC_PATH_PKCS11)/pkcs11-spy.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_PKCS11)/pkcs11-spy.c -o ./$(REPVER)/pkcs11-spy.o

################################################################################

./$(REPVER)/system.o :  $(SRC_PATH_SYSTEM)/system.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_PATH_SYSTEM)/system.c -o ./$(REPVER)/system.o

################################################################################

./$(REPVER)/sys_config.o :  ../../../common/sys_config.c 
	$(CC) $(CFLAGS) $(INCLUDES) ../../../common/sys_config.c -o ./$(REPVER)/sys_config.o
