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
 *         Autoconfigures the akes_mac_driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

/* configure Contiki */
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC akes_mac_driver
#undef CSMA_CONF_WITH_AKES
#define CSMA_CONF_WITH_AKES 1
#undef NBR_TABLE_CONF_WITH_FIND_REMOVABLE
#define NBR_TABLE_CONF_WITH_FIND_REMOVABLE 0
#undef SICSLOWPAN_CONF_INIT_QUEUEBUF
#define SICSLOWPAN_CONF_INIT_QUEUEBUF 0
#undef PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES
#define PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES 1
#undef LLSEC802154_CONF_USES_FRAME_COUNTER
#define LLSEC802154_CONF_USES_FRAME_COUNTER 1
#undef CSPRNG_CONF_ENABLED
#define CSPRNG_CONF_ENABLED 1
#undef FRAME802154_CONF_VERSION
#define FRAME802154_CONF_VERSION FRAME802154_IEEE802154_2015

/* configure AKES */
#undef AKES_MAC_CONF_ENABLED
#define AKES_MAC_CONF_ENABLED 1
#undef AKES_MAC_CONF_DECORATED_MAC
#define AKES_MAC_CONF_DECORATED_MAC contikimac_driver
#undef AKES_MAC_CONF_STRATEGY
#define AKES_MAC_CONF_STRATEGY contikimac_strategy
#undef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_CONF_WITH_GROUP_KEYS 1

#ifndef AKES_MAC_CONF_UNICAST_SEC_LVL
#define AKES_MAC_CONF_UNICAST_SEC_LVL 6
#endif /* AKES_MAC_CONF_UNICAST_SEC_LVL */

#if ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 1)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 6
#elif ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 2)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 8
#elif ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 3)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 10
#else
#error "unsupported security level"
#endif

#ifndef AKES_MAC_CONF_BROADCAST_SEC_LVL
#define AKES_MAC_CONF_BROADCAST_SEC_LVL AKES_MAC_CONF_UNICAST_SEC_LVL
#endif /* AKES_MAC_CONF_BROADCAST_SEC_LVL */

#if ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 1)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 6
#elif ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 2)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 8
#elif ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 3)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 10
#else
#error "unsupported security level"
#endif

/* configure FRAMERs */
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER contikimac_framer
#undef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER akes_mac_framer
#undef AKES_MAC_CONF_DECORATED_FRAMER
#define AKES_MAC_CONF_DECORATED_FRAMER streamer_802154
#ifndef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 0
#endif /* LLSEC802154_CONF_USES_AUX_HEADER */

/* configure POTR */
#ifndef POTR_CONF_ENABLED
#define POTR_CONF_ENABLED 1
#endif /* POTR_CONF_ENABLED */

#if POTR_CONF_ENABLED
#undef AES_128_CONF_WITH_LOCKING
#define AES_128_CONF_WITH_LOCKING 1
#undef NBR_TABLE_CONF_WITH_LOCKING
#define NBR_TABLE_CONF_WITH_LOCKING 1
#undef AKES_NBR_CONF_WITH_LOCKING
#define AKES_NBR_CONF_WITH_LOCKING 1
#undef RADIO_ASYNC_CONF_WITH_CHECKSUM
#define RADIO_ASYNC_CONF_WITH_CHECKSUM 0
#undef SICSLOWPAN_CONF_MAC_MAX_PAYLOAD
#define SICSLOWPAN_CONF_MAC_MAX_PAYLOAD 127
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER contikimac_framer
#undef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER akes_mac_framer
#undef AKES_MAC_CONF_DECORATED_FRAMER
#define AKES_MAC_CONF_DECORATED_FRAMER potr_framer
#undef POTR_CONF_WITH_CONTIKIMAC_FRAMER
#define POTR_CONF_WITH_CONTIKIMAC_FRAMER 1

/* configure ILOS */
#ifndef ILOS_CONF_ENABLED
#define ILOS_CONF_ENABLED 1
#endif /* ILOS_CONF_ENABLED */

#if ILOS_CONF_ENABLED
#undef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 0
#undef ANTI_REPLAY_CONF_WITH_SUPPRESSION
#define ANTI_REPLAY_CONF_WITH_SUPPRESSION 0
#undef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_CONF_WITH_INDICES 0
#undef LLSEC802154_CONF_USES_FRAME_COUNTER
#define LLSEC802154_CONF_USES_FRAME_COUNTER 0
#undef CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#define CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE 0
#undef AKES_DELETE_CONF_WITH_UPDATEACKS
#define AKES_DELETE_CONF_WITH_UPDATEACKS 0
#endif /* ILOS_CONF_ENABLED */
#endif /* POTR_CONF_ENABLED */