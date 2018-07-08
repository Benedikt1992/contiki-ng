CONTIKI_PROJECT = revocation_border
all: $(CONTIKI_PROJECT)

CONTIKI=../../..

SMALL=1

# 0 => run in cooja; 1 => run on openmote
ON_MOTE=0

ifeq ($(ON_MOTE),1)
	CFLAGS += -DON_MOTE
	MAKE_MAC = MAKE_MAC_CSL
else
	MAKE_MAC = MAKE_MAC_CSMA
endif

MODULES += os/net/app-layer/coap
MODULES += os/net/security/akes
CFLAGS += -DREVOCATION_BORDER

# This enables to communicate between host and cooja simulation. Use 'make connect-router-cooja TARGET=cooja'
MODULES += os/services/rpl-border-router

MAKE_NET = MAKE_NET_IPV6

include $(CONTIKI)/Makefile.include
