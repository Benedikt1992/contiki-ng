/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Creates and parses the ContikiMAC header.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/contikimac-framer.h"
#include "dev/radio-async.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include <string.h>

#ifdef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define DECORATED_FRAMER CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#else /* CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER */
#define DECORATED_FRAMER framer_802154
#endif /* CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER */

extern const struct framer DECORATED_FRAMER;

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ContikiMAC-framer"
#define LOG_LEVEL LOG_LEVEL_MAC

/*---------------------------------------------------------------------------*/
static int
hdr_length(void)
{
  return DECORATED_FRAMER.length() + CONTIKIMAC_FRAMER_HEADER_LEN;
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  uint8_t *hdrptr;
  uint8_t *dataptr;
  int hdr_len;
  int padding_bytes;

  /* allocate space for the ContikiMAC header */
  if(packetbuf_hdralloc(CONTIKIMAC_FRAMER_HEADER_LEN) == 0) {
    LOG_ERR("too large header\n");
    return FRAMER_FAILED;
  }
  hdrptr = packetbuf_hdrptr();
  hdrptr[0] = 0;

  /* create and secure the outgoing frame by calling the decorated framer */
  hdr_len = DECORATED_FRAMER.create();
  if(hdr_len < 0) {
    LOG_ERR("decorated framer failed\n");
    return FRAMER_FAILED;
  }

  /* write original datalen and pad if necessary */
  dataptr = packetbuf_dataptr();
  dataptr[-1] = packetbuf_datalen();
  padding_bytes = CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE
      - packetbuf_totlen()
      - RADIO_ASYNC_CHECKSUM_LEN;
  if(padding_bytes > 0) {
    memset(dataptr + packetbuf_datalen(), 0, padding_bytes);
    packetbuf_set_datalen(packetbuf_datalen() + padding_bytes);
  }

  return hdr_len + CONTIKIMAC_FRAMER_HEADER_LEN;
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  int hdr_len;
  uint8_t *dataptr;

  /* the decorated framer should not unsecure at this point */
  hdr_len = DECORATED_FRAMER.parse();
  if(hdr_len < 0) {
    return FRAMER_FAILED;
  }

  /* process the ContikiMAC header */
  if(!packetbuf_hdrreduce(CONTIKIMAC_FRAMER_HEADER_LEN)) {
    LOG_ERR("packetbuf_hdrreduce failed\n");
    return FRAMER_FAILED;
  }
  dataptr = packetbuf_dataptr();
  packetbuf_set_datalen(dataptr[-1]);
  dataptr[-1] = 0;

  return hdr_len + CONTIKIMAC_FRAMER_HEADER_LEN;
}
/*---------------------------------------------------------------------------*/
const struct framer contikimac_framer = {
  hdr_length,
  create,
  parse
};
/*---------------------------------------------------------------------------*/
