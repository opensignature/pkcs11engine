nobase_lib_LTLIBRARIES = \
    pkcs11.la

pkcs11_la_LDFLAGS = \
    -avoid-version -module -share \
    -Wl -version-number @VERSION_MAJOR@:@VERSION_MINOR@:@VERSION_PATCH@

pkcs11_la_CPPFLAGS = \
    @OPENSSL_INCLUDES@

pkcs11_la_CFLAGS =  -Wno-deprecated-declarations \
    -pthread

pkcs11_la_SOURCES = \
    e_pkcs11.c \
    e_pkcs11_err.c \
    e_pkcs11.h \
    e_pkcs11_eng.c \
    e_pkcs11_err.h \
    pkcs11.h \
    pkcs11t.h \
    pkcs11f.h \
    dso.h
