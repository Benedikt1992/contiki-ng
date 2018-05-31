CONTIKI_PROJECT = revocation
all: $(CONTIKI_PROJECT)

CONTIKI=../../..

SMALL=1

# for upload to hardware
# MAKE_MAC = MAKE_MAC_CSL

# for upload to simulator
MAKE_MAC = MAKE_MAC_CSMA
MODULES += os/net/security/akes

MAKE_NET = MAKE_NET_NULLNET

include $(CONTIKI)/Makefile.include
