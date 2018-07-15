//#define REVOCATION_BORDER
/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 */

/**
 * \file
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */
#ifdef REVOCATION_BORDER

#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"
#include "sys/timer.h"
#include "net/security/akes/akes-revocation.h"
#include "sys/log.h"
#define LOG_MODULE "AKES_REV_COAP"
#define LOG_LEVEL LOG_LEVEL_DBG

struct akes_revocation_request_state state;

/*---------------------------------------------------------------------------
 * Setup a state object
 */
/*---------------------------------------------------------------------------*/
static int
index_of(const char *data, int offset, int len, uint8_t c)
{
  if(offset < 0) {
    return offset;
  }
  for(; offset < len; offset++) {
    if(data[offset] == c) {
      return offset;
    }
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
struct akes_revocation_request_state
akes_revocation_setup_state(linkaddr_t *addr_revoke, uint8_t amount_dst, linkaddr_t *addr_dsts, uint8_t *new_keys,linkaddr_t *new_neighbors,  const coap_endpoint_t *requestor) {
  struct akes_revocation_request_state state;

  state.addr_revoke = addr_revoke;
  state.amount_dst = amount_dst;
  state.addr_dsts = addr_dsts;
  state.new_keys = new_keys;
  state.amount_new_neighbors = 0;
  state.new_neighbors = new_neighbors;
  state.amount_replies = 0;

  uint8_t n = coap_endpoint_snprint(state.requestor, 48, requestor);
  uint8_t start = index_of(state.requestor, 0, n, '[');
  uint8_t end = index_of(state.requestor, start, n, ']');
  for (int i = end +1; i < n; ++i) {
    state.requestor[i] = 0;
  }
  state.len_requestor = end + 1;

  return state;
}

static void
akes_revocation_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{ //TODO Add Description
  // TODO Make it failsafe
  static const uint8_t *payload;
  coap_get_payload(request, &payload);

  static  uint8_t control_byte;
  static  linkaddr_t revoke_node;
  static  uint8_t number_dsts;


  control_byte = *payload++;
  if(control_byte == 2) {
    // ToDo reset revocation process
  }
  revoke_node = *(linkaddr_t *)(void*)payload;
  payload += LINKADDR_SIZE;
  number_dsts = *payload++;

  static linkaddr_t dsts[AKES_REVOCATION_MAX_DSTS];
  memcpy(dsts, payload, LINKADDR_SIZE * number_dsts);
  static linkaddr_t new_neighbors[AKES_REVOCATION_MAX_NEW_NEIGHBORS];

  state = akes_revocation_setup_state(&revoke_node, number_dsts, dsts, NULL, new_neighbors, coap_get_src_endpoint(request));
  akes_revocation_revoke_node(&state);

  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_status_code(response, CONTENT_2_05);
  coap_set_payload(response, "OK", 2);
  return;
}

/*---------------------------------------------------------------------------*/
RESOURCE(res_akes_revocation,
         "title=\"AKES_Revoke\"",
         NULL,
         akes_revocation_post_handler,
         NULL,
         NULL);
/*---------------------------------------------------------------------------*/

#endif /* REVOCATION_BORDER */
