/*
 * Copyright (c) 2017, Hasso-Plattner-Institut.
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

#include "contiki.h"
#include "sys/etimer.h"
#include "net/security/akes/akes-nbr.h"
#include "net/security/akes/akes-revocation.h"
#include "os/net/linkaddr.h"
#include "sys/log.h"
#define LOG_MODULE "REV_BORDER"
#define LOG_LEVEL LOG_LEVEL_DBG

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

PROCESS(revocation_border_process, "revocation_border_process");
AUTOSTART_PROCESSES(&revocation_border_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(revocation_border_process, ev, data)
{
  static struct etimer periodic_timer;

  PROCESS_BEGIN();

  etimer_set(&periodic_timer, CLOCK_SECOND * 5);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    etimer_reset(&periodic_timer);

#if ON_MOTE
    struct akes_nbr_entry *entry;
    entry = akes_nbr_head();
    if(entry && entry->permanent) {
      LOG_INFO("sending revocation\n");
      akes_revocation_revoke_node(akes_nbr_get_addr(entry));
    }
    break;
#else
    linkaddr_t nodes[5];
    for (int j = 0; j < 5; ++j) {
      for(unsigned int i = 0; i < LINKADDR_SIZE; i++) {
        if(i == 0) {
          nodes[j].u8[i] = 0x00 | (j+1);
        } else {
          nodes[j].u8[i] = 0x00;
        }
      }
      LOG_INFO_LLADDR(&nodes[j]);
      LOG_INFO_("\n");
    }

    linkaddr_t mal_node;
    for(unsigned int i = 0; i < LINKADDR_SIZE; i++) {
      if(i == 0) {
        mal_node.u8[i] = 0x02;
      } else {
        mal_node.u8[i] = 0x00;
      }
    }

    /* simulate the process */
    struct akes_revocation_request_state state;
    LOG_INFO("TEST ");
    LOG_INFO_LLADDR(&mal_node);
    LOG_INFO_("\n");
    state = akes_revocation_setup_state(&mal_node, 1, &linkaddr_node_addr, NULL);
    LOG_INFO("sending revocation\n");
    akes_revocation_revoke_node(&state);

    etimer_set(&periodic_timer, CLOCK_SECOND);
    for (int k = 0; k < 5; ++k) {
      if(state.amount_replies >= 1) {
        break;
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
      etimer_reset(&periodic_timer);
      LOG_DBG("WAIT\n");
    }

    linkaddr_t dst_list[2];

    for(unsigned int i = 0; i < LINKADDR_SIZE; i++) {
      if(i == 0) {
        mal_node.u8[i] = 0x02;
      } else {
        mal_node.u8[i] = 0x00;
      }
    }
    for (int j = 0; j < 5; ++j) {
      for(unsigned int i = 0; i < LINKADDR_SIZE; i++) {
        if(i == 0) {
          nodes[j].u8[i] = 0x00 | (j+1);
        } else {
          nodes[j].u8[i] = 0x00;
        }
      }
      LOG_INFO_LLADDR(&nodes[j]);
      LOG_INFO_("\n");
    }
    dst_list[0] = nodes[2];
    dst_list[1] = nodes[3];
    LOG_INFO("TEST2 ");
    LOG_INFO_LLADDR(&mal_node);
    LOG_INFO_("\n");
    state = akes_revocation_setup_state(&mal_node, 2, (linkaddr_t *)dst_list, NULL);
    LOG_DBG("NEW initialized state with reply amount: %02x\n", state.amount_replies);

    LOG_INFO("sending revocation\n");
    akes_revocation_revoke_node(&state);

    etimer_set(&periodic_timer, CLOCK_SECOND);
    for (int k = 0; k < 5; ++k) {
      if(state.amount_replies >= 2) {
        break;
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
      etimer_reset(&periodic_timer);
      LOG_DBG("WAIT\n");
    }

    //TODO WARUM ist das bitte nicht mehr 0??? Das wird nirgends angefasst.
    LOG_DBG("FINISHED WAITING with replies: %02x\n", state.amount_replies);
    break;
#endif // ON_MOTE
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
