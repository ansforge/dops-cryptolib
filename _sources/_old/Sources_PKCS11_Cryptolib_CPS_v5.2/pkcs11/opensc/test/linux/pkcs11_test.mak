CC=gcc
AR=ar

PROJ=pkcs11_test

#SRC_PATH=../src
#SRC_PATH_SCCONF=$(SRC_PATH)/scconf
#SRC_PATH_LIBOPENSC=$(SRC_PATH)/libopensc
#SRC_PATH_COMMON=$(SRC_PATH)/common
#SRC_PATH_PKCS15INIT=$(SRC_PATH)/pkcs15init
#SRC_PATH_PKCS11=$(SRC_PATH)/pkcs11
#SRC_PATH_SYSTEM=../unix/src

PATH_TEST=.
SRC_PATH_TEST=../src
SYS_SRC_PATH_TEST=$(PATH_TEST)/src

# INCLUDES=-I../unix/src \
#  -I$(SRC_PATH)/include \
#	-I$(SRC_PATH)/include/opensc \
# -I$(SRC_PATH)/libopensc \
#	-I../../openssl/include_linux \
#	-I../../openssl/include \
#	-I../../../common
	
#	-I../../LibTool/include \
	
INCLUDES_TEST=-I$(PATH_TEST)/src \
  -I$(SRC_PATH_TEST) \
	-I../../../../common \
	-I../../../../common/linux/src \
	-I../../src/include/opensc \
	-I../../src/include \
	-I../../src/pkcs11 \
	-I../../../openssl/include_linux \
	-I../../../openssl/include


LIBDIR=-L./$(REPVER) \
			 -L../../../openssl/$(REPVER_OPENSSL)


################################################################################


OBJFILES_TST_LIB=$(PATH_TEST)/$(REPVER)/test.o \
  $(PATH_TEST)/$(REPVER)/testsystem.o \
  $(PATH_TEST)/$(REPVER)/testEncryptDecrypt.o \
  $(PATH_TEST)/$(REPVER)/testHTMLResults.o \
  $(PATH_TEST)/$(REPVER)/testSignatureVerifSign.o \
  $(PATH_TEST)/$(REPVER)/testSignatureVerifSignRsaPss.o \
  $(PATH_TEST)/$(REPVER)/testTools.o \
  $(PATH_TEST)/$(REPVER)/testDigest.o \
  $(PATH_TEST)/$(REPVER)/testCpsData.o
  
exe:    ../../linux/$(REPVER)/libcps3_pkcs11_lux.so \
		./$(REPVER)/$(PROJ)

./$(REPVER)/$(PROJ):    $(OBJFILES_TST_LIB)
	$(CC) $(LDFLAGS_TST_LIB) $(OBJFILES_TST_LIB) -o $(PATH_TEST)/$(REPVER)/$(PROJ) $(LIBDIR) -lcrypto.0.9.8n -lpthread $(LIBS_TST) -ldl -lc 
			
cleanup :
	rm -f $(REPVER)/*.o
	rm -f $(REPVER)/pkcs11_test
	rm -f $(REPVER)/build.lst
	rm -f $(REPVER)/build.err
	
	
	

################################################################################
# SOURCE FILES COMPILATION
################################################################################

$(PATH_TEST)/$(REPVER)/test.o :  $(SRC_PATH_TEST)/test.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/test.cpp -o $(PATH_TEST)/$(REPVER)/test.o

################################################################################

$(PATH_TEST)/$(REPVER)/testsystem.o :  $(SYS_SRC_PATH_TEST)/testsystem.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SYS_SRC_PATH_TEST)/testsystem.cpp -o $(PATH_TEST)/$(REPVER)/testsystem.o

################################################################################

$(PATH_TEST)/$(REPVER)/testEncryptDecrypt.o :  $(SRC_PATH_TEST)/testEncryptDecrypt.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testEncryptDecrypt.cpp -o $(PATH_TEST)/$(REPVER)/testEncryptDecrypt.o

################################################################################

$(PATH_TEST)/$(REPVER)/testHTMLResults.o :  $(SRC_PATH_TEST)/testHTMLResults.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testHTMLResults.cpp -o $(PATH_TEST)/$(REPVER)/testHTMLResults.o

	
################################################################################

$(PATH_TEST)/$(REPVER)/testSignatureVerifSign.o :  $(SRC_PATH_TEST)/testSignatureVerifSign.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testSignatureVerifSign.cpp -o $(PATH_TEST)/$(REPVER)/testSignatureVerifSign.o

################################################################################

$(PATH_TEST)/$(REPVER)/testSignatureVerifSignRsaPss.o :  $(SRC_PATH_TEST)/testSignatureVerifSignRsaPss.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testSignatureVerifSignRsaPss.cpp -o $(PATH_TEST)/$(REPVER)/testSignatureVerifSignRsaPss.o
	
################################################################################

$(PATH_TEST)/$(REPVER)/testTools.o :  $(SRC_PATH_TEST)/testTools.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testTools.cpp -o $(PATH_TEST)/$(REPVER)/testTools.o

################################################################################

$(PATH_TEST)/$(REPVER)/testDigest.o :  $(SRC_PATH_TEST)/testDigest.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testDigest.cpp -o $(PATH_TEST)/$(REPVER)/testDigest.o

################################################################################

$(PATH_TEST)/$(REPVER)/testCpsData.o :  $(SRC_PATH_TEST)/testCpsData.cpp 
	$(CC) $(CFLAGS_TST) $(INCLUDES_TEST) $(SRC_PATH_TEST)/testCpsData.cpp -o $(PATH_TEST)/$(REPVER)/testCpsData.o
