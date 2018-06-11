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
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-revocation.h"

MEMB(route_memb, linkaddr_t, AKES_REVOCATION_MAX_ROUTE_LEN);

static struct cmd_broker_subscription subscription;
static enum cmd_broker_result on_revocation_revoke(uint8_t *payload);
static enum cmd_broker_result on_revocation_ack(uint8_t *payload);
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
 * Handler for received revoke node messages
 * payload - the payload of the received message
 *
 */
static enum cmd_broker_result
on_revocation_revoke(uint8_t *payload)
{
    LOG_INFO("received revocation Revoke\n");
    LOG_INFO("Payload: %02x\n", payload[0] & 0xff);

    uint8_t hop_index = *payload++;
    uint8_t hop_count = *payload++;
    linkaddr_t *addr_route = (linkaddr_t *)(void*)payload;
    payload += LINKADDR_SIZE * hop_count+1;

    linkaddr_t *addr_revoke = (linkaddr_t *)(void*)payload;

    if (hop_index < 1 || hop_index > hop_count) return CMD_BROKER_ERROR;

    if (hop_index == hop_count) {
        //revoke the addr_revoke node
        //TODO: revoke the node

        //reverse the route
        for (uint8_t i = 0; i <= hop_count; i++) {
            memcpy(&((linkaddr_t *)route_memb.mem)[i], &addr_route[hop_count-i], LINKADDR_SIZE);
        }
        akes_revocation_send_ack(addr_revoke, 1, hop_count, addr_route, NULL);
    } else {
        //forward the message
        akes_revocation_send_revoke(addr_revoke, hop_index+1, hop_count, ((linkaddr_t *)route_memb.mem), payload);
    }

    return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
/*
 * Handler for received ack messages
 * payload - the payload of the received message
 *
 */
static enum cmd_broker_result
on_revocation_ack(uint8_t *payload)
{
    LOG_INFO("received revocation ACK\n");
    LOG_INFO("Payload: %02x\n", payload[0] & 0xff);

    uint8_t hop_index = *payload++;
    uint8_t hop_count = *payload++;
    linkaddr_t *addr_route = (linkaddr_t *)(void*)payload;
    payload += LINKADDR_SIZE * hop_count+1;

    linkaddr_t *addr_revoke = (linkaddr_t *)(void*)payload;

    if (hop_index < 1 || hop_index > hop_count) return CMD_BROKER_ERROR;

    if (hop_index == hop_count) {
        //TODO: digest the information, calculate new route and send the stuff out

    } else {
        //forward the message
        akes_revocation_send_ack(addr_revoke, hop_index+1, hop_count, addr_route, payload);
    }

    return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
/*
 * public AKES API for revoking a node
 * addr_revoke - the address of the node that should be revoked
 */
void akes_revocation_revoke_node(const linkaddr_t * addr_revoke) {
    LOG_INFO("revokation_send_revoke\n");
    uint8_t *payload;
    uint8_t payload_len;

    payload = akes_mac_prepare_command(AKES_REVOCATION_REVOKE, addr_revoke ); // points to payload memory after cmd_id
    *payload = 0xAF;
    payload_len = 2; // cmd_id is the first byte of the payload
    packetbuf_set_datalen(payload_len);
    akes_mac_send_command_frame();
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

    //the hop addresses
    for (uint8_t i = 0; i <= hop_count; i++) {
        memcpy(&payload[i], &addr_route[i], LINKADDR_SIZE);
        payload += LINKADDR_SIZE;
    }

    if (data != NULL) {
        //copy data from previous payload

        //the address of the revoked node
        memcpy(payload, data, LINKADDR_SIZE);
        data += LINKADDR_SIZE;

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
    for (uint8_t i = 0; i <= hop_count; i++) {
        memcpy(&payload[i], &addr_route[i], LINKADDR_SIZE);
        payload += LINKADDR_SIZE;
    }

    if (data != NULL) {
        //copy data from previous payload

        //the address of the revoked node
        memcpy(payload, data, LINKADDR_SIZE);
        data += LINKADDR_SIZE;

        //the number of neighbors
        uint8_t nbr_count = payload[0];

        //the neighbors
        memcpy(payload, data, LINKADDR_SIZE * nbr_count);
        payload += LINKADDR_SIZE * nbr_count;
    }
    else {
        /* TODO: encrypt the following information with the session key */

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
            if(next->refs[AKES_NBR_PERMANENT]) {
                (*nbr_count)++;
                memcpy(payload, akes_nbr_get_addr(next) , LINKADDR_SIZE);
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
    subscription.on_command = on_command;
    cmd_broker_subscribe(&subscription);
}
