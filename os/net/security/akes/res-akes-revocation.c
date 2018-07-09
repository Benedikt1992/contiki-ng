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
#include "sys/log.h"
#define LOG_MODULE "AKES_REV_COAP"
#define LOG_LEVEL LOG_LEVEL_DBG

static void
akes_revocation_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const uint8_t *payload;
//  uint8_t  payload_length;
//  payload_length =
  coap_get_payload(request, &payload);
//  uint8_t  rep_length = *payload - '0';

  LOG_DBG("Payload: %016x", *payload);

//  if(payload_length > 1 || rep_length > 9) {
//    coap_set_header_content_format(response, TEXT_PLAIN);
//    coap_set_status_code(response, BAD_OPTION_4_02);
//    coap_set_payload(response, "Please enter a single number between 0-9", 40);
//    return;
//  }

  uint8_t *content = (uint8_t *)"AKES_REV!";
  coap_set_header_content_format(response, APPLICATION_OCTET_STREAM);
  coap_set_status_code(response, CONTENT_2_05);
  coap_set_payload(response, content, 4);
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
