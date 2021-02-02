# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

.PHONY: all build clean run

OE_CRYPTO_LIB?= mbedtls

EDL:= datasealing

define oe-config
$(or $(shell pkg-config oe$(strip $1)),\
	$(error Have you sourced 'openenclaverc'?))
endef

define find-seal-plugins
$(wildcard $(LIBDIR)/enclave/objects-$1/oeseal_*/*.o)
endef

ENCLAVE_CFLAGS:= $(call oe-config,enclave-$(C_COMPILER) --cflags)
ENCLAVE_CXXFLAGS:= $(call oe-config,enclave-$(CXX_COMPILER) --cflags)
ENCLAVE_LDFLAGS:= $(call oe-config,enclave-$(C_COMPILER) --libs)
ENCLAVE_LDFLAGS+= $(call oe-config,enclave-$(C_COMPILER) --variable=$(OE_CRYPTO_LIB)libs)

HOST_CFLAGS:= $(call oe-config,host-$(C_COMPILER) --cflags)
HOST_CXXFLAGS:= $(call oe-config,host-$(CXX_COMPILER) --cflags)
HOST_LDFLAGS:= $(call oe-config,host-$(C_COMPILER) --libs)

INCDIR:= $(call oe-config,enclave-$(CXX_COMPILER) --variable=includedir)
LIBDIR:= $(call oe-config,enclave-$(C_COMPILER) --variable=libdir)/openenclave

SEAL_PLUGINS:= $(or	\
	$(call find-seal-plugins,Release),	\
	$(call find-seal-plugins,Debug),	\
	$(error No sealing plug-ins found! Files under $(LIBDIR)/enclave:	\
		$(shell find $(LIBDIR)/enclave -type f -printf %P\\n)))

EDL_OUT_T:= $(addprefix common/$(EDL),_t.c _t.h _args.h)
EDL_OUT_U:= $(addprefix host/$(EDL),_u.c _u.h _args.h)

HEADERS:= $(wildcard *.h */*.h)
ENCLAVES:= $(addsuffix /enclave.signed,enclave_a_v1 enclave_a_v2 enclave_b)
HOST:= host/host

all: build

%/enclave.signed: %/enclave %/data-sealing.conf
	oesign sign -e $< -c $(filter %.conf,$^) -k $(filter %.pem,$^)

$(foreach v,a b,$(eval $(filter enclave_$v%,$(ENCLAVES)): private_$v.pem))

%/enclave: %/ecalls.cpp.o common/dispatcher.cpp.o	\
	$(addsuffix .o,$(filter-out %.h,$(EDL_OUT_T))) $(SEAL_PLUGINS)
	$(CC) -o $@ $^ $($(ENCLAVE_OR_HOST)_LDFLAGS)

%/enclave: ENCLAVE_OR_HOST:= ENCLAVE

%.cpp.o: %.cpp $(ENC_HDRS) $(EDL_OUT_T) $(EDL_OUT_U)
	$(CC) $($(ENCLAVE_OR_HOST)_CXXFLAGS) -I. -std=c++11 -c $< -o $@

%.c.o: %.c $(ENC_HDRS) $(EDL_OUT_T) $(EDL_OUT_U)
	$(CC) $($(ENCLAVE_OR_HOST)_CFLAGS) -I. -c $< -o $@

%.pem:
	openssl genrsa -out $@ -3 3072

$(HOST): $(addsuffix .o,$(wildcard $(dir $(HOST))*.cpp) $(filter-out %.h,$(EDL_OUT_U)))
	$(CC) -o $@ $^ $($(ENCLAVE_OR_HOST)_LDFLAGS) -lstdc++

$(HOST): ENCLAVE_OR_HOST:= HOST

$(EDL_OUT_T) $(EDL_OUT_U): $(EDL).edl
	oeedger8r $<	\
		--trusted-dir $(sort $(dir $(EDL_OUT_T)))	\
		--untrusted-dir $(sort $(dir $(EDL_OUT_U)))	\
		--search-path $(INCDIR) --search-path $(INCDIR)/openenclave/edl/sgx

build: $(ENCLAVES) $(HOST)

run: build
	$(HOST) $(ENCLAVES)

clean:
	-rm -f *.pem $(ENCLAVES) $(HOST) $(basename $(ENCLAVES))	\
		$(EDL_OUT_T) $(EDL_OUT_U) */*.cpp.o */*.c.o
