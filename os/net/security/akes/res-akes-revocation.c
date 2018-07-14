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
#include "sys/etimer.h"
//#include "net/security/akes/akes.h"
//#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-revocation.h"
#include "sys/log.h"
#define LOG_MODULE "AKES_REV_COAP"
#define LOG_LEVEL LOG_LEVEL_DBG

PROCESS(revocation_process, "revocation_process");

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
  revoke_node = *(linkaddr_t *)(void*)payload++;
  number_dsts = *payload++;

  static linkaddr_t dsts[AKES_REVOCATION_MAX_DSTS];
  memcpy(dsts, payload, LINKADDR_SIZE * number_dsts);
//  static linkaddr_t new_neighbors[AKES_REVOCATION_MAX_NEW_NEIGHBORS];

  static struct akes_revocation_request_state state;
  state = akes_revocation_setup_state(&revoke_node, number_dsts, dsts, NULL);
  LOG_DBG("Process starting....\n");
  process_start(&revocation_process, &state);

//  static int k;
//  for(k=0; k<100; ++k) {
//    LOG_DBG("Process running....\n");
//    process_run();
//  }
//  while (process_is_running(&revocation_process)) {
//    LOG_DBG("Process running....\n");
//    process_poll(&revocation_process);
//    process_run();
//  }
  process p = PROCESS_CURRENT();
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_status_code(response, CONTENT_2_05);
  char buf[25];
  sprintf(buf, "Got %d replies", state.amount_replies);
  coap_set_payload(response, buf, 25);
  return;
}

PROCESS_THREAD(revocation_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Starting revocation process\n");
//  akes_revocation_revoke_node(&state);
//
  static struct etimer periodic_timer;
  etimer_set(&periodic_timer, CLOCK_SECOND);
  static int k;
  for (k = 0; k < 5; ++k) {
//    if(state.amount_replies >= number_dsts) {
//      break;
//    }
    LOG_INFO("WAIT\n");
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    etimer_reset(&periodic_timer);
  }
//                LOG_DBG("%x%x%x", control_byte, revoke_node, number_dsts, payload_length, dsts, new_neighbors, state,k);
  PROCESS_END();
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
