CONTIKI_PROJECT = revocation
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
	MODULES += os/net/security/akes
endif

MAKE_NET = MAKE_NET_NULLNET

include $(CONTIKI)/Makefile.include
