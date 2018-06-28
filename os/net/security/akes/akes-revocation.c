/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 *         ??
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES"
#define LOG_LEVEL LOG_LEVEL_DBG

#include "net/mac/cmd-broker.h"
#include "net/packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-revocation.h"

struct traversal_entry {
    //for iterating through all visited nodes
    struct traversal_entry *next;
    //for iterating through the node topology
    struct traversal_entry *parent;
    linkaddr_t addr;
};

MEMB(traversal_memb, struct traversal_entry, AKES_REVOCATION_MAX_QUEUE);
LIST(traversal_list);
static linkaddr_t addr_revoke_node;
static uint8_t traversal_index;

static struct cmd_broker_subscription subscription;
static enum cmd_broker_result on_revocation_revoke(uint8_t *payload);
static enum cmd_broker_result on_revocation_ack(uint8_t *payload);
/*---------------------------------------------------------------------------*/
static struct traversal_entry *
traversal_entry_from_addr(const linkaddr_t *addr)
{
    struct traversal_entry *n = list_head(traversal_list);
    while(n != NULL) {
        if(linkaddr_cmp(&n->addr, addr)) {
            return n;
        }
        n = list_item_next(n);
    }
    return NULL;
}
/*---------------------------------------------------------------------------*/
/*
 * Multiplexer for received messages
 */
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
    switch(cmd_id) {
        case AKES_REVOCATION_REVOKE:
            return on_revocation_revoke(payload);
        case AKES_REVOCATION_ACK:
            return on_revocation_ack(payload);
        default:
            return CMD_BROKER_UNCONSUMED;
    }
}
/*---------------------------------------------------------------------------*/
/*
 * This method builds the link layer route to the node 'entry' and triggers the revoke message
 */
void
process_node(struct traversal_entry *entry) {
    uint8_t route_length = 0;
    linkaddr_t route[AKES_REVOCATION_MAX_ROUTE_LEN];
    struct traversal_entry *next = entry;

    traversal_index++;

    //build the route from receiver upwards in network topology
    while(next) {
        route[AKES_REVOCATION_MAX_ROUTE_LEN - route_length -1] = next->addr;
        next = next->parent;
        route_length++;
    }

    uint8_t hop_count = route_length-1;
    akes_revocation_send_revoke(&addr_revoke_node, 1, hop_count, &route[AKES_REVOCATION_MAX_ROUTE_LEN - route_length], NULL);
}
/*---------------------------------------------------------------------------*/
/*
 * private AKES method for revoking a node
 * addr_revoke - the address of the node that should be revoked
 */
void
akes_revocation_revoke_node_internal(const linkaddr_t * addr_revoke) {
    LOG_INFO("locally revoked ");
    LOG_INFO_LLADDR(addr_revoke);
    LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------
 * Setup a state object
 */
struct akes_revocation_state
akes_revocation_setup_state(linkaddr_t *addr_revoke, uint8_t amount_dst, linkaddr_t *addr_dsts, uint8_t *new_keys) {
  struct akes_revocation_state state;

  state.addr_revoke = addr_revoke;
  state.amount_dst = amount_dst;
  state.addr_dsts = addr_dsts;
  state.new_keys = new_keys;
  return state;
}
/*---------------------------------------------------------------------------*/
/*
 * public AKES API for revoking a node
 * addr_revoke - the address of the node that should be revoked
 * TODO Add neighbors to state object
 */
int8_t
akes_revocation_revoke_node(struct akes_revocation_state *state) {
  if (addr_revoke_node && !linkaddr_cmp(&addr_revoke_node, state->addr_revoke)) {
    return AKES_REVOCATION_ALREADY_IN_PROGRESS;
  }
  if (!addr_revoke_node) {
      addr_revoke_node = *state->addr_revoke;
  }

  for (int i = 0; i < state->amount_dst; ++i) {
    if (linkaddr_cmp(&state->addr_dsts[i], &linkaddr_node_addr)) {
      struct traversal_entry *root_entry;

      //Revoke the node locally
      akes_revocation_revoke_node_internal(&addr_revoke_node);
      //Save us in the traversal List
      root_entry = memb_alloc(&traversal_memb);
      root_entry->addr = linkaddr_node_addr;
      root_entry->parent = NULL;
      list_add(traversal_list, root_entry);
    }
    else {
      if (linkaddr_cmp(&state->addr_dsts[i], state->addr_revoke)) {
        LOG_INFO("Containing ");
        LOG_INFO_LLADDR(state->addr_revoke);
        LOG_INFO_(" as destination in request. Going to ignore.\n");
        continue;
      }
      LOG_INFO("Going to send revocation message to ");
      LOG_INFO_LLADDR(&state->addr_dsts[i]);
      LOG_INFO_("\n");

      process_node(new_entry); //TODO
    }
  }

//  struct traversal_entry *root_entry;
//
//    LOG_INFO("revokation_send_revoke for node: ");
//    LOG_INFO_LLADDR(state->addr_revoke);
//    LOG_INFO_("\n");
//
//    traversal_index = 0;
//
//    struct traversal_entry *new_entry;
//    struct akes_nbr_entry *next;
//    next = akes_nbr_head();
//    while(next) {
//        if (linkaddr_cmp(state->addr_revoke, akes_nbr_get_addr(next))) {
//          LOG_INFO("Containing ");
//          LOG_INFO_LLADDR(state->addr_revoke);
//          LOG_INFO_(" as direct neighbor. Going to ignore.\n");
//          next = akes_nbr_next(next);
//          continue;
//        }
//        if(next->permanent) {
//            new_entry = memb_alloc(&traversal_memb);
//            new_entry->parent = root_entry;
//            new_entry->addr = *akes_nbr_get_addr(next);
//            list_add(traversal_list, new_entry);
//
//            LOG_INFO("Going to send revocation message to ");
//            LOG_INFO_LLADDR(&new_entry->addr);
//            LOG_INFO_("\n");
//
//            process_node(new_entry);
//        }
//        next = akes_nbr_next(next);
//    }
}
/*---------------------------------------------------------------------------*/
/*
 * Handler for received revoke node messages
 * payload - the payload of the received message
 *
 * payload content: | hop_index | hop_count | addr_sender,addr_hop1..addr_dest | addr_revoke |
 */
static enum cmd_broker_result
on_revocation_revoke(uint8_t *payload)
{
    LOG_INFO("received revocation Revoke for ");

    uint8_t hop_index = *payload++;
    uint8_t hop_count = *payload++;
    linkaddr_t *addr_route = (linkaddr_t *)(void*)payload;
    payload += LINKADDR_SIZE * (hop_count+1);

    linkaddr_t *addr_revoke = (linkaddr_t *)(void*)payload;

    LOG_INFO_LLADDR(addr_revoke);
    LOG_INFO_("\n");

    if (hop_index < 1 || hop_index > hop_count) return CMD_BROKER_ERROR;

    if (hop_index == hop_count) {
        LOG_INFO("revoke message is for myself.\n");

        //revoke the addr_revoke node
        akes_revocation_revoke_node_internal(addr_revoke);

        //reverse the route
        linkaddr_t temp_buffer[AKES_REVOCATION_MAX_ROUTE_LEN];
        for (uint8_t i = 0; i < hop_count+1; i++) {
            temp_buffer[i] = addr_route[hop_count-i];
        }
        akes_revocation_send_ack(addr_revoke, 1, hop_count, temp_buffer, NULL);
    } else {
        //forward the message
        LOG_INFO("revoke message is going to be forwarded.\n");
        akes_revocation_send_revoke(addr_revoke, hop_index+1, hop_count, addr_route, payload);
    }

    return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
/*
 * Handler for received ack messages
 * payload - the payload of the received message
 *
 * payload: | hop_index | hop_count | addr_sender,addr_hop1..addr_dest | addr_revoke | nbr_count | addr_nbr1..addr_nbr? |
 */
static enum cmd_broker_result
on_revocation_ack(uint8_t *payload)
{
    //TODO: Does the answer of on revocation interrupt this message? And does it change the payload pointer content?
    LOG_INFO("received revocation ACK for ");

    uint8_t hop_index = *payload++;
    uint8_t hop_count = *payload++;
    linkaddr_t addr_route[hop_count +1];
    linkaddr_t *addr_route_payload = (linkaddr_t *)(void*)payload;
    for (int j = 0; j <= hop_count ; ++j) {
      addr_route[j] = addr_route_payload[j];
    }
    payload += LINKADDR_SIZE * (hop_count+1);

    uint8_t *forwarded_payload = payload;

    linkaddr_t *addr_revoke = (linkaddr_t *)(void*)payload;
    payload += LINKADDR_SIZE;
    uint8_t nbr_count = *payload++;
    linkaddr_t *nbr_addrs = (linkaddr_t *)(void*)payload;
    payload += LINKADDR_SIZE * nbr_count;

    LOG_INFO_LLADDR(addr_revoke);
    LOG_INFO_(" from ");
    LOG_INFO_LLADDR(addr_route);
    LOG_INFO_("\n");

    if (hop_index < 1 || hop_index > hop_count) return CMD_BROKER_ERROR;

    if (hop_index == hop_count) {
        LOG_INFO("revocation ack is for myself.\n");
        if (!linkaddr_cmp(addr_revoke,&addr_revoke_node)) {
            //TODO addr_revoke_node will have changed if there is a second call!
            LOG_INFO("INVALID addr_revoke. ack dropped.\n");
            return CMD_BROKER_ERROR;
        }
        struct traversal_entry *entry = traversal_entry_from_addr(&addr_route[0]);
        if (!entry) return CMD_BROKER_ERROR;

        struct traversal_entry *new_entry;
        for (uint8_t i = 0; i < nbr_count; i++) {
            if (linkaddr_cmp(addr_revoke, &nbr_addrs[i])) {
              LOG_INFO("Received ");
              LOG_INFO_LLADDR(addr_revoke);
              LOG_INFO_(" as neighbor of ");
              LOG_INFO_LLADDR(addr_route);
              LOG_INFO_(". Going to ignore.\n");
              continue;
            }
            // Check whether we already processed this node
            if (traversal_entry_from_addr(&nbr_addrs[i])) continue;

            new_entry = memb_alloc(&traversal_memb);
            new_entry->addr = nbr_addrs[i];
            new_entry->parent = entry;
            list_add(traversal_list, new_entry);

            LOG_INFO("Going to send revocation message to ");
            LOG_INFO_LLADDR(&new_entry->addr);
            LOG_INFO_("\n");

            process_node(new_entry);
        }
    } else {
        //forward the message
        LOG_INFO("revocation ack is going to be forwarded.\n");
        akes_revocation_send_ack(addr_revoke, hop_index+1, hop_count, addr_route, forwarded_payload);
    }

    return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
/*
 * Prepare & Send an node revoke message
 * addr_revoke - the address of the node that should be revoked
 * hop_index - the index in source route of the next hop, index = 0 points to the sending address, index = hop_count to the destination
 * hop_count - the number of hops one the route (eg route with 3 nodes is two hops long)
 * addr_route - an array of the addresses including the start & destination node address
 *
 * | cmd_id | hop_index | hop_count | addr_sender,addr_hop1..addr_dest | addr_revoke |
 */
void akes_revocation_send_revoke(const linkaddr_t * addr_revoke, const uint8_t hop_index, const uint8_t hop_count, const linkaddr_t *addr_route, const uint8_t *data){
    //TODO remove debug output
    LOG_INFO("revokation_send_revoke\n");

    uint8_t *payload;
    uint8_t payload_len;

    payload = akes_mac_prepare_command(AKES_REVOCATION_REVOKE, &addr_route[hop_index] ); // points to payload memory after cmd_id

    //the current hop
    *payload = hop_index;
    payload++;

    //the number of hops
    *payload = hop_count;
    payload++;
    LOG_INFO("Call Params: ");
    LOG_INFO_LLADDR(addr_revoke);
    LOG_INFO_(", %d, %d, ", hop_index, hop_count);
    LOG_INFO_("Route: ");

    //the hop addresses
    //we have hop_count+1 addresses in the route
    for (uint8_t i = 0; i < hop_count+1; i++) {
        memcpy(payload, &addr_route[i], LINKADDR_SIZE);
        payload += LINKADDR_SIZE;
        LOG_INFO_LLADDR(&addr_route[i]);
        LOG_INFO_(", ");
    }
    LOG_INFO_("\n");

    if (data) {
        //copy data from previous payload

        //the address of the revoked node
        memcpy(payload, data, LINKADDR_SIZE);
        data += LINKADDR_SIZE;
        payload += LINKADDR_SIZE;

    } else {
        /* TODO: encrypt the following information with the session key */

        //node address that should be revoked
        memcpy(payload, addr_revoke, LINKADDR_SIZE);
        payload += LINKADDR_SIZE;
    }

    payload_len = payload - ((uint8_t *)packetbuf_hdrptr());

    packetbuf_set_datalen(payload_len);
    akes_mac_send_command_frame();
}
/*---------------------------------------------------------------------------*/
/*
 * Prepare & Send an acknowledge message
 * addr_revoke - the address of the node that should be revoked
 * hop_index - the index in source route of the next hop, index = 0 points to the sending address, index = hop_count to the destination
 * hop_count - the number of hops one the route (eg route with 3 nodes is two hops long)
 * addr_route - an array of the addresses including the start & destination node address
 *
 * | cmd_id | hop_index | hop_count | addr_sender,addr_hop1..addr_dest | addr_revoke | nbr_count | addr_nbr1..addr_nbr? |
 *
 */
void akes_revocation_send_ack(const linkaddr_t * addr_revoke, const uint8_t hop_index, const uint8_t hop_count, const linkaddr_t *addr_route, const uint8_t *data) {
    LOG_INFO("revokation_send_ack\n");
    uint8_t *payload;
    uint8_t payload_len;

    payload = akes_mac_prepare_command(AKES_REVOCATION_ACK, &addr_route[hop_index] ); // points to payload memory after cmd_id

    //the current hop
    *payload = hop_index;
    payload++;

    //the number of hops
    *payload = hop_count;
    payload++;

    //the hop addresses
    //we have hop_count+1 addresses in the route
    for (uint8_t i = 0; i < hop_count+1; i++) {
        memcpy(payload, &addr_route[i], LINKADDR_SIZE);
        payload += LINKADDR_SIZE;
    }

    if (data) {
        //copy data from previous payload

        //the address of the revoked node
        memcpy(payload, data, LINKADDR_SIZE);
        data += LINKADDR_SIZE;
        payload += LINKADDR_SIZE;

        //the number of neighbors
        uint8_t nbr_count = *data++;
        *payload = nbr_count;
        payload++;

        //the neighbors
        memcpy(payload, data, LINKADDR_SIZE * nbr_count);
        payload += LINKADDR_SIZE * nbr_count;
    }
    else {
        LOG_INFO("build new ack message\n");
        // TODO: encrypt the following information with the session key

        //the address of the revoked node
        memcpy(payload, addr_revoke, LINKADDR_SIZE);
        payload += LINKADDR_SIZE;

        //reserve space for the number of neighbors
        uint8_t *nbr_count = payload;
        payload++;

        //the neighbor addresses
        struct akes_nbr_entry *next;

        *nbr_count = 0;
        next = akes_nbr_head();
        while(next) {
            if(next->permanent) {
                (*nbr_count)++;
                linkaddr_t *nbr_addr = akes_nbr_get_addr(next);
                LOG_INFO("nbr entry: ");
                LOG_INFO_LLADDR(nbr_addr);
                LOG_INFO_("\n");

                memcpy(payload, nbr_addr , LINKADDR_SIZE);
                payload += LINKADDR_SIZE;
            }
            next = akes_nbr_next(next);
        }
    }

    payload_len = payload - ((uint8_t *)packetbuf_hdrptr());

    packetbuf_set_datalen(payload_len);
    akes_mac_send_command_frame();
}
/*---------------------------------------------------------------------------*/
/*
 * Initializer routine for the akes revocation
 */
void
akes_revocation_init(void) {
    memb_init(&traversal_memb);
    list_init(traversal_list);
    subscription.on_command = on_command;
    cmd_broker_subscribe(&subscription);
}
