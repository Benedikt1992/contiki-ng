//#define REVOCATION_BORDER
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

#include "net/mac/cmd-broker.h"
#include "net/packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-revocation.h"
#ifdef REVOCATION_BORDER
  #include "sys/ctimer.h"
  #include "coap-engine.h"
  #include "coap-blocking-api.h"
  #include "coap-log.h"
  extern coap_resource_t res_akes_revocation;
  PROCESS(request_responder, "request_responder");
#endif

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES"
#define LOG_LEVEL LOG_LEVEL_DBG

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
struct akes_revocation_request_state *request_state;

uint16_t sent_acks;
uint16_t sent_revokes;
uint16_t received_acks;
uint16_t received_revokes;

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


    //build the route from receiver upwards in network topology
    while(next) {
        route[AKES_REVOCATION_MAX_ROUTE_LEN - route_length -1] = next->addr;
        next = next->parent;
        route_length++;
    }

    uint8_t hop_count = route_length-1;
    LOG_DBG("Will reach ");
    LOG_DBG_LLADDR(&entry->addr);
    LOG_DBG_(" in %d hops\n", hop_count);
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
/*---------------------------------------------------------------------------*/
/*
 * private AKES method for adding a new discovered neighbor to the state object
 * nbr_addr - the address of the new neighbor
 * TODO Check if neighbor store has free space. If not what should happen?
 */
static void
akes_revocation_add_new_neighbor_to_state(const linkaddr_t *nbr_addr) {
  for (int i = 0; i < request_state->amount_new_neighbors; ++i) {
    if(linkaddr_cmp(&request_state->addr_dsts[i], nbr_addr)) {
      return;
    }
  }
  LOG_INFO("Adding ");
  LOG_INFO_LLADDR(nbr_addr);
  LOG_INFO_(" as new neighbor\n");
  request_state->new_neighbors[request_state->amount_new_neighbors] = *nbr_addr;
  (request_state->amount_new_neighbors)++;
}
/*---------------------------------------------------------------------------*/
/*
 * private AKES method for adding a new replies to the state object
 * reply_addr - the address of the new neighbor
 * TODO Check if reply store has free space. If not what should happen?
 */
static void
akes_revocation_add_new_reply_to_state(const linkaddr_t *reply_addr) {
  for (int i = 0; i < request_state->amount_replies; ++i) {
    if(linkaddr_cmp(&request_state->revoke_reply_secrets[i], reply_addr)) {
      return;
    }
  }
  LOG_INFO("Adding ");
  LOG_INFO_LLADDR(reply_addr);
  LOG_INFO_(" as new reply\n");
  request_state->revoke_reply_secrets[request_state->amount_replies] = *reply_addr;
  (request_state->amount_replies)++;
}
/*---------------------------------------------------------------------------*/
/*
 * private AKES method for checking if a mac address is in an array of addresses
 * node - the address to be checked
 * list - the array of addresses
 * n - number of elements in the list
 */
static int
node_in_list(linkaddr_t *node, linkaddr_t *list, uint8_t n)
{
  for (int i = 0; i < n; ++i) {
    if(linkaddr_cmp(node, &list[i])) {
      return 1;
    }
  }
  return 0;
}
void
akes_revocation_terminate(void)
{
  struct traversal_entry *n = list_chop(traversal_list);
  while(n != NULL) {
    memb_free(&traversal_memb, n);
    n = list_chop(traversal_list);
  }


  addr_revoke_node = linkaddr_null;
  LOG_INFO("Revocation process terminated.\n");
}
/*---------------------------------------------------------------------------*/
/*
 * public AKES API for revoking a node
 * addr_revoke - the address of the node that should be revoked
 */
int8_t
akes_revocation_revoke_node(struct akes_revocation_request_state *state) {
  struct traversal_entry * next;
  struct traversal_entry *new_entry;
  struct akes_nbr_entry *next_entry;
  LOG_DBG("revoke node with state addr_revoke: ");
  LOG_DBG_LLADDR(state->addr_revoke);
  LOG_DBG_(", amount_dst: %d, destinations: ", state->amount_dst);
  for (int j = 0; j < state->amount_dst; ++j) {
    LOG_DBG_LLADDR(&state->addr_dsts[j]);
    LOG_DBG_(" ");
  }
  LOG_DBG_("\n");


  request_state = state;

  if (!linkaddr_cmp(&addr_revoke_node, &linkaddr_null) && !linkaddr_cmp(&addr_revoke_node, request_state->addr_revoke)) {
    LOG_WARN("Received request for revocation of ");
    LOG_WARN_LLADDR(request_state->addr_revoke);
    LOG_WARN_(" but process is in progress for ");
    LOG_WARN_LLADDR(&addr_revoke_node);
    LOG_WARN_("\n");
    return AKES_REVOCATION_ALREADY_IN_PROGRESS;
  }
  if (linkaddr_cmp(&addr_revoke_node, &linkaddr_null)) {
      addr_revoke_node = *request_state->addr_revoke;
  }

  for (int i = 0; i < request_state->amount_dst; ++i) {
    if (linkaddr_cmp(&request_state->addr_dsts[i], &linkaddr_node_addr)) {
      // Containing self as dst. This is the start of the process.
      struct traversal_entry *root_entry;
      LOG_INFO("Starting new revocation process for node ");
      LOG_INFO_LLADDR(request_state->addr_revoke);
      LOG_INFO_("\n");

      //Revoke the node locally
      akes_revocation_revoke_node_internal(&addr_revoke_node);
      //Save us in the traversal List
      root_entry = memb_alloc(&traversal_memb);
      root_entry->addr = linkaddr_node_addr;
      root_entry->parent = NULL;
      list_add(traversal_list, root_entry);

      next_entry = akes_nbr_head();
      while(next_entry) {
        if(next_entry->permanent) {
          linkaddr_t *nbr_addr = akes_nbr_get_addr(next_entry);

          akes_revocation_add_new_neighbor_to_state(nbr_addr);

          new_entry = memb_alloc(&traversal_memb);
          new_entry->parent = root_entry;
          new_entry->addr = *akes_nbr_get_addr(next_entry);
          list_add(traversal_list, new_entry);
        }
        next_entry = akes_nbr_next(next_entry);
      }
      akes_revocation_add_new_reply_to_state(&linkaddr_node_addr);
    } else {
      // Process any other node in the network
      if (linkaddr_cmp(&request_state->addr_dsts[i], request_state->addr_revoke)) {
        LOG_INFO("Containing revocation goal ");
        LOG_INFO_LLADDR(request_state->addr_revoke);
        LOG_INFO_(" as destination in request. Going to ignore.\n");
        continue;
      }

      next = traversal_entry_from_addr(&request_state->addr_dsts[i]);

      if (!next) {
        LOG_ERR("No route found for ");
        LOG_ERR_LLADDR(&request_state->addr_dsts[i]);
        LOG_ERR_(". Going to abort.\n");
        return AKES_REVOCATION_ROUTE_NOT_FOUND;
      }

      LOG_INFO("Going to send revocation message to ");
      LOG_INFO_LLADDR(&request_state->addr_dsts[i]);
      LOG_INFO_("\n");
      process_node(next);
    }
  }
#ifdef REVOCATION_BORDER
  if(process_is_running(&request_responder)) {
    LOG_INFO("Responder process is in progress. Going to exit...\n");
    process_exit(&request_responder);
  }
  process_start(&request_responder, NULL);
#endif
  return AKES_REVOCATION_SUCCESS;
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
    LOG_INFO_(" from address ");
    LOG_INFO_LLADDR(addr_route);
    LOG_INFO_("\n");

    received_revokes++;
    LOG_DBG("package count received_revokes: %d\n", received_revokes);

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
        temp_buffer[0] = temp_buffer[0];
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

    received_acks++;
    LOG_DBG("package count received_acks: %d\n", received_acks);

    if (hop_index < 1 || hop_index > hop_count) return CMD_BROKER_ERROR;

    if (hop_index == hop_count) {
        LOG_INFO("revocation ack is for myself.\n");
        if (!linkaddr_cmp(addr_revoke,&addr_revoke_node)) {
            LOG_INFO("INVALID addr_revoke. ack dropped.\n");
            return CMD_BROKER_ERROR;
        }
        struct traversal_entry *entry = traversal_entry_from_addr(&addr_route[0]);
        if (!entry) return CMD_BROKER_ERROR;

        if(!node_in_list(&addr_route[0], request_state->addr_dsts, request_state->amount_dst)) {
          LOG_INFO("Received reply from ");
          LOG_INFO_LLADDR(&addr_route[0]);
          LOG_INFO_(" is not part of the current destinations\n");
          return CMD_BROKER_ERROR;
        }


        struct traversal_entry *new_entry;
        for (uint8_t i = 0; i < nbr_count; i++) {
          // Check whether we already processed this node
          if (traversal_entry_from_addr(&nbr_addrs[i])) continue;

          if (linkaddr_cmp(addr_revoke, &nbr_addrs[i])) {
              LOG_INFO("Received ");
              LOG_INFO_LLADDR(addr_revoke);
              LOG_INFO_(" as neighbor of ");
              LOG_INFO_LLADDR(addr_route);
              LOG_INFO_(". Going to ignore.\n");
              akes_revocation_add_new_neighbor_to_state(&nbr_addrs[i]);
              continue;
            }


            new_entry = memb_alloc(&traversal_memb);
            new_entry->addr = nbr_addrs[i];
            new_entry->parent = entry;
            list_add(traversal_list, new_entry);

            akes_revocation_add_new_neighbor_to_state(&nbr_addrs[i]);
        }
      akes_revocation_add_new_reply_to_state(addr_route);
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
    sent_revokes++;
    LOG_DBG("package count sent_revokes: %d\n", sent_revokes);

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
        LOG_DBG("NO DATA\n");
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
    sent_acks++;
    LOG_DBG("package count sent_acks: %d\n", sent_acks);
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
#ifdef REVOCATION_BORDER
static void
akes_revocation_init_coap(void *ptr) {
  LOG_DBG("activate resource of akes\n");
  coap_activate_resource(&res_akes_revocation, AKES_REVOCATION_URI_PATH);
}
#endif
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
    sent_acks = 0;
    sent_revokes = 0;
    received_acks = 0;
    received_revokes = 0;
#ifdef REVOCATION_BORDER
    static struct ctimer timer;
    ctimer_set(&timer, CLOCK_SECOND, akes_revocation_init_coap, NULL);
#endif
}
/*---------------------------------------------------------------------------*/
#ifdef REVOCATION_BORDER
void
akes_coap_response_handler(coap_message_t *response)
{
  LOG_INFO("Received status code %d\n", response->code);
}

/*---------------------------------------------------------------------------
 * This process waits until one request is fulfilled and sends the result to the requestor
 * Message format:
 * |border router mac address | number of replies | reply addresses | number of new neighbors | addresses of neighbors |
 */
PROCESS_THREAD(request_responder, ev, data)
{
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();
    static struct etimer periodic_timer;
    static coap_message_t response[1];
    coap_endpoint_parse(request_state->requestor, request_state->len_requestor, &server_ep);
    etimer_set(&periodic_timer, CLOCK_SECOND);
#if ON_MOTE
    static int k;
    for (k = 0; k < AKES_REVOCATION_REQUEST_TIMEOUT; ++k) {
      if(request_state->amount_replies >= request_state->amount_dst) {
        break;
      }
      LOG_DBG("Still waiting for replies. Received %d/%d\n", request_state->amount_replies, request_state->amount_dst);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
      etimer_reset(&periodic_timer);
    }
#else // Don't timeout in simulation
    while(request_state->amount_replies < request_state->amount_dst) {
      LOG_DBG("Still waiting \n");
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
      etimer_reset(&periodic_timer);
    }
#endif /* ON_MOTE */
    LOG_INFO("Going to send response to ");
    LOG_INFO_COAP_EP(&server_ep);
    LOG_INFO_("\n");

    if( request_state->amount_replies < request_state->amount_dst ) {
      LOG_INFO("Didn't receive all replies. Expected replies: ");
      for (int j = 0; j < request_state->amount_dst; ++j) {
        LOG_INFO_LLADDR(&request_state->addr_dsts[j]);
        LOG_INFO_(", ");
      }
      LOG_INFO_(" only received the following replies: ");
      for (int i = 0; i < request_state->amount_replies; ++i) {
        LOG_INFO_LLADDR(&request_state->revoke_reply_secrets[i]);
        LOG_INFO_(", ");
      }
      LOG_INFO_("\n");
    }

    coap_init_message(response, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(response, AKES_REVOCATION_URI_PATH);

    uint8_t msg[AKES_REVOCATION_REPLY_BUF_SIZE];
    uint8_t *payload = msg;

    *(linkaddr_t *)(void *)payload = linkaddr_node_addr;
    payload += LINKADDR_SIZE;
    *payload = request_state->amount_replies;
    payload++;
    *payload = request_state->amount_new_neighbors;
    payload++;
    memcpy(payload,request_state->revoke_reply_secrets,request_state->amount_replies * LINKADDR_SIZE);
    payload += request_state->amount_replies * LINKADDR_SIZE;

    memcpy(payload,request_state->new_neighbors,request_state->amount_new_neighbors * LINKADDR_SIZE);

    coap_set_payload(response, msg, sizeof(msg) - 1);

    COAP_BLOCKING_REQUEST(&server_ep, response, akes_coap_response_handler);

  PROCESS_END();
}
#endif /* REVOCATION_BORDER */
/*---------------------------------------------------------------------------*/
