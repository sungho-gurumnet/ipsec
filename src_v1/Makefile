CC = gcc
OBJS = SA.o SAD.o SPD.o authenticator.o decryptor.o encryptor.o s_window.o IPSec_module.o checksum.o 
SRCS = $(OBJS:%.o=%.c)
LIBS = -lcrypto  
CFLAGS = -g -O2 -Wall -I ../../sdk/include -D_TRANSPORT_ 
#CFLAGS = -pg  		
TARGET = IPSec_module
 
.SUFFIXES : .c .o
 
all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

depend : 
	gccmakedep $(SRCS)
				 
clean :
	rm -f $(OBJS) $(TARGET)
		 
# DO NOT DELETE
esp.o: esp.c SPD.h SP.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdint.h /usr/include/stdint.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h ip.h SAD.h SA.h s_window.h \
 esp.h decryptor.h /usr/include/openssl/des.h \
 /usr/include/openssl/e_os2.h /usr/include/openssl/opensslconf.h \
 /usr/include/openssl/des_old.h /usr/include/openssl/symhacks.h \
 /usr/include/openssl/ui_compat.h /usr/include/openssl/ui.h \
 /usr/include/openssl/crypto.h /usr/include/stdlib.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stddef.h \
 /usr/include/x86_64-linux-gnu/bits/waitflags.h \
 /usr/include/x86_64-linux-gnu/bits/waitstatus.h /usr/include/endian.h \
 /usr/include/x86_64-linux-gnu/bits/endian.h \
 /usr/include/x86_64-linux-gnu/bits/byteswap.h \
 /usr/include/x86_64-linux-gnu/sys/types.h \
 /usr/include/x86_64-linux-gnu/bits/types.h \
 /usr/include/x86_64-linux-gnu/bits/typesizes.h /usr/include/time.h \
 /usr/include/x86_64-linux-gnu/sys/select.h \
 /usr/include/x86_64-linux-gnu/bits/select.h \
 /usr/include/x86_64-linux-gnu/bits/sigset.h \
 /usr/include/x86_64-linux-gnu/bits/time.h \
 /usr/include/x86_64-linux-gnu/sys/sysmacros.h \
 /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h /usr/include/alloca.h \
 /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h \
 /usr/include/wchar.h /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdarg.h \
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \
 /usr/include/x86_64-linux-gnu/bits/sys_errlist.h \
 /usr/include/openssl/stack.h /usr/include/openssl/safestack.h \
 /usr/include/openssl/opensslv.h /usr/include/openssl/ossl_typ.h \
 /usr/include/string.h /usr/include/xlocale.h /usr/include/malloc.h
decryptor.o: decryptor.c decryptor.h /usr/include/openssl/des.h \
 /usr/include/openssl/e_os2.h /usr/include/openssl/opensslconf.h \
 /usr/include/openssl/des_old.h /usr/include/openssl/symhacks.h \
 /usr/include/openssl/ui_compat.h /usr/include/openssl/ui.h \
 /usr/include/openssl/crypto.h /usr/include/stdlib.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stddef.h \
 /usr/include/x86_64-linux-gnu/bits/waitflags.h \
 /usr/include/x86_64-linux-gnu/bits/waitstatus.h /usr/include/endian.h \
 /usr/include/x86_64-linux-gnu/bits/endian.h \
 /usr/include/x86_64-linux-gnu/bits/byteswap.h \
 /usr/include/x86_64-linux-gnu/sys/types.h \
 /usr/include/x86_64-linux-gnu/bits/types.h \
 /usr/include/x86_64-linux-gnu/bits/typesizes.h /usr/include/time.h \
 /usr/include/x86_64-linux-gnu/sys/select.h \
 /usr/include/x86_64-linux-gnu/bits/select.h \
 /usr/include/x86_64-linux-gnu/bits/sigset.h \
 /usr/include/x86_64-linux-gnu/bits/time.h \
 /usr/include/x86_64-linux-gnu/sys/sysmacros.h \
 /usr/include/x86_64-linux-gnu/bits/pthreadtypes.h /usr/include/alloca.h \
 /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h \
 /usr/include/wchar.h /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdarg.h \
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \
 /usr/include/x86_64-linux-gnu/bits/sys_errlist.h \
 /usr/include/openssl/stack.h /usr/include/openssl/safestack.h \
 /usr/include/openssl/opensslv.h /usr/include/openssl/ossl_typ.h \
 /usr/include/string.h /usr/include/xlocale.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdint.h /usr/include/stdint.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h SA.h s_window.h ip.h
encryptor.o: encryptor.c encryptor.h
authenticator.o: authenticator.c authenticator.h
s_window.o: s_window.c s_window.h
SAD.o: SAD.c SAD.h SA.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdint.h /usr/include/stdint.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h s_window.h ip.h esp.h
SPD.o: SPD.c SPD.h SP.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.7/include/stdint.h /usr/include/stdint.h \
 /usr/include/features.h /usr/include/x86_64-linux-gnu/bits/predefs.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/include/x86_64-linux-gnu/bits/wchar.h ip.h
