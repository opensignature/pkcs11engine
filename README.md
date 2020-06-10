# pkcs11engine

work in progress

### build

```
./bootstrap
./configure
make
```

### usage

Configuring the engine in the config file:
```
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11.so
