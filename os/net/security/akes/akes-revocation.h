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
 *         akes-revocation.h
 * \author
 *         ??
 */

#ifndef AKES_REVOCATION_H_
#define AKES_REVOCATION_H_

#include "net/security/akes/akes.h"
#include "net/security/akes/akes-nbr.h"

#ifdef REVOCATION_BORDER
  #include "coap-engine.h"
#endif


#define AKES_REVOCATION_MAX_ROUTE_LEN 100 //define this value based on the depth of the network topology
#define AKES_REVOCATION_MAX_QUEUE 128 //120
#define AKES_REVOCATION_MAX_NEW_NEIGHBORS 60
#define AKES_REVOCATION_MAX_DSTS 100
#define AKES_REVOCATION_REQUEST_TIMEOUT 10 //seconds
#define AKES_REVOCATION_URI_PATH "akes/revoke"
#define AKES_REVOCATION_REPLY_BUF_SIZE (LINKADDR_SIZE * (1 + AKES_REVOCATION_MAX_DSTS + AKES_REVOCATION_MAX_NEW_NEIGHBORS) + 2)

#define AKES_REVOCATION_SUCCESS 0
#define AKES_REVOCATION_ERROR 255
#define AKES_REVOCATION_ALREADY_IN_PROGRESS 1
#define AKES_REVOCATION_ROUTE_NOT_FOUND 2

struct akes_revocation_request_state {
    linkaddr_t *addr_revoke;
    uint8_t amount_dst;
    linkaddr_t *addr_dsts;
    uint8_t *new_keys; //TODO This value needs to be adjusted to key type
    linkaddr_t revoke_reply_secrets[AKES_REVOCATION_MAX_DSTS];
    uint8_t amount_replies;
    uint8_t amount_new_neighbors;
    linkaddr_t new_neighbors[AKES_REVOCATION_MAX_NEW_NEIGHBORS];
    char requestor[48]; //maximum string "coap://[1111:1111:1111:1111:1111:1111:1111:1111]"
    uint8_t len_requestor;
};
int8_t akes_revocation_revoke_node(struct akes_revocation_request_state *request_state);
void akes_revocation_send_revoke(const linkaddr_t * addr_revoke, const uint8_t hop_index, const uint8_t hop_count, const linkaddr_t *addr_route, const uint8_t *data);
void akes_revocation_send_ack(const linkaddr_t * addr_revoke, const uint8_t hop_index, const uint8_t hop_count, const linkaddr_t *addr_route, const uint8_t *data);
void akes_revocation_init(void);
void akes_revocation_terminate(void);

#endif /* AKES_REVOCATION_H_ */
