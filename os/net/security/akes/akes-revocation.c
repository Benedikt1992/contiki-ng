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
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-revocation.h"

static struct cmd_broker_subscription subscription;
static enum cmd_broker_result on_hello(uint8_t *payload);
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
    switch(cmd_id) {
        case AKES_REVOCATION_HELLO:
            return on_hello(payload);
        default:
            return CMD_BROKER_UNCONSUMED;
    }
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_hello(uint8_t *payload)
{
    LOG_INFO("received revocation HELLO\n");
    LOG_INFO("Payload: %02x\n", payload[0] & 0xff);

    /* -----------------------
     * Do whatever is necessary when a node received a revocation message (authenticate?, remove, reply)
     * TODO: rename method to something useful
     */

    return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
void akes_revokation_send_revoke(struct akes_nbr_entry * entry) {
    LOG_INFO("revokation_send_revoke\n");
    uint8_t *payload;
    uint8_t payload_len;

    payload = akes_mac_prepare_command(AKES_REVOCATION_HELLO, akes_nbr_get_addr(entry) ); // points to payload memory after cmd_id
    payload[0] = 0x00;
    payload_len = 2; // cmd_id is the first byte of the payload
    packetbuf_set_datalen(payload_len);
    akes_mac_send_command_frame();
}
/*---------------------------------------------------------------------------*/
void
akes_revokation_init(void) {
    subscription.on_command = on_command;
    cmd_broker_subscribe(&subscription);
}
