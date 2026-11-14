# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_CRYPTO_LIB_AES)			+= libaes.o
libaes-y					:= aes.o

obj-$(CONFIG_CRYPTO_LIB_ARC4)			+= libarc4.o
libarc4-y					:= arc4.o

# blake2s is used by the random number generator, so it is always built in.
obj-y						+= libblake2s.o
libblake2s-y					:= blake2s.o
libblake2s-$(CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC)	+= blake2s-generic.o

obj-$(CONFIG_CRYPTO_LIB_DES)			+= libdes.o
libdes-y					:= des.o

obj-$(CONFIG_CRYPTO_LIB_SHA256)			+= libsha256.o
libsha256-y					:= sha256.o

ifneq ($(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS),y)
libblake2s-y					+= blake2s-selftest.o
endif
