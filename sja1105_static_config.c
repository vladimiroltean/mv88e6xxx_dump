// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2016-2018, NXP Semiconductors
 * Copyright (c) 2018-2019, Vladimir Oltean <olteanv@gmail.com>
 */
#include "sja1105_static_config.h"
#include <inttypes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define ETHER_CRC32_POLY				0x04C11DB7

static void sja1105_packing(void *buf, u64 *val, int start, int end,
			    size_t len, enum packing_op op)
{
	int rc;

	rc = packing(buf, val, start, end, len, op, QUIRK_LSW32_IS_FIRST);
	if (!rc)
		return;

	printf("Invalid use of packing API: start %d end %d returned %d\n",
	       start, end, rc);
}

static u32 bitrev32(u32 val)
{
	/* Use implementation from packing.c */
	return bit_reverse(val, 32);
}

static u32 crc32_add(u32 crc, u8 byte)
{
	u32 byte32 = bitrev32(byte);
	int i;

	for (i = 0; i < 8; i++) {
		if ((crc ^ byte32) & BIT(31)) {
			crc <<= 1;
			crc ^= ETHER_CRC32_POLY;
		} else {
			crc <<= 1;
		}
		byte32 <<= 1;
	}
	return crc;
}

/* Little-endian Ethernet CRC32 of data packed as big-endian u32 words */
static u32 sja1105_crc32(void *buf, size_t len)
{
	unsigned int i;
	u64 chunk;
	u32 crc;

	/* seed */
	crc = 0xFFFFFFFF;
	for (i = 0; i < len; i += 4) {
		sja1105_packing(buf + i, &chunk, 31, 0, 4, UNPACK);
		crc = crc32_add(crc, chunk & 0xFF);
		crc = crc32_add(crc, (chunk >> 8) & 0xFF);
		crc = crc32_add(crc, (chunk >> 16) & 0xFF);
		crc = crc32_add(crc, (chunk >> 24) & 0xFF);
	}
	return bitrev32(~crc);
}

static size_t sja1105et_avb_params_entry_packing(void *buf, void *entry_ptr,
						 enum packing_op op)
{
	const size_t size = SJA1105ET_SIZE_AVB_PARAMS_ENTRY;
	struct sja1105_avb_params_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->destmeta, 95, 48, size, op);
	sja1105_packing(buf, &entry->srcmeta,  47,  0, size, op);
	return size;
}

size_t sja1105pqrs_avb_params_entry_packing(void *buf, void *entry_ptr,
					    enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY;
	struct sja1105_avb_params_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->cas_master, 126, 126, size, op);
	sja1105_packing(buf, &entry->destmeta,   125,  78, size, op);
	sja1105_packing(buf, &entry->srcmeta,     77,  30, size, op);
	return size;
}

static size_t sja1105et_general_params_entry_packing(void *buf, void *entry_ptr,
						     enum packing_op op)
{
	const size_t size = SJA1105ET_SIZE_GENERAL_PARAMS_ENTRY;
	struct sja1105_general_params_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->vllupformat, 319, 319, size, op);
	sja1105_packing(buf, &entry->mirr_ptacu,  318, 318, size, op);
	sja1105_packing(buf, &entry->switchid,    317, 315, size, op);
	sja1105_packing(buf, &entry->hostprio,    314, 312, size, op);
	sja1105_packing(buf, &entry->mac_fltres1, 311, 264, size, op);
	sja1105_packing(buf, &entry->mac_fltres0, 263, 216, size, op);
	sja1105_packing(buf, &entry->mac_flt1,    215, 168, size, op);
	sja1105_packing(buf, &entry->mac_flt0,    167, 120, size, op);
	sja1105_packing(buf, &entry->incl_srcpt1, 119, 119, size, op);
	sja1105_packing(buf, &entry->incl_srcpt0, 118, 118, size, op);
	sja1105_packing(buf, &entry->send_meta1,  117, 117, size, op);
	sja1105_packing(buf, &entry->send_meta0,  116, 116, size, op);
	sja1105_packing(buf, &entry->casc_port,   115, 113, size, op);
	sja1105_packing(buf, &entry->host_port,   112, 110, size, op);
	sja1105_packing(buf, &entry->mirr_port,   109, 107, size, op);
	sja1105_packing(buf, &entry->vlmarker,    106,  75, size, op);
	sja1105_packing(buf, &entry->vlmask,       74,  43, size, op);
	sja1105_packing(buf, &entry->tpid,         42,  27, size, op);
	sja1105_packing(buf, &entry->ignore2stf,   26,  26, size, op);
	sja1105_packing(buf, &entry->tpid2,        25,  10, size, op);
	return size;
}

/* TPID and TPID2 are intentionally reversed so that semantic
 * compatibility with E/T is kept.
 */
size_t sja1105pqrs_general_params_entry_packing(void *buf, void *entry_ptr,
						enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_GENERAL_PARAMS_ENTRY;
	struct sja1105_general_params_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->vllupformat, 351, 351, size, op);
	sja1105_packing(buf, &entry->mirr_ptacu,  350, 350, size, op);
	sja1105_packing(buf, &entry->switchid,    349, 347, size, op);
	sja1105_packing(buf, &entry->hostprio,    346, 344, size, op);
	sja1105_packing(buf, &entry->mac_fltres1, 343, 296, size, op);
	sja1105_packing(buf, &entry->mac_fltres0, 295, 248, size, op);
	sja1105_packing(buf, &entry->mac_flt1,    247, 200, size, op);
	sja1105_packing(buf, &entry->mac_flt0,    199, 152, size, op);
	sja1105_packing(buf, &entry->incl_srcpt1, 151, 151, size, op);
	sja1105_packing(buf, &entry->incl_srcpt0, 150, 150, size, op);
	sja1105_packing(buf, &entry->send_meta1,  149, 149, size, op);
	sja1105_packing(buf, &entry->send_meta0,  148, 148, size, op);
	sja1105_packing(buf, &entry->casc_port,   147, 145, size, op);
	sja1105_packing(buf, &entry->host_port,   144, 142, size, op);
	sja1105_packing(buf, &entry->mirr_port,   141, 139, size, op);
	sja1105_packing(buf, &entry->vlmarker,    138, 107, size, op);
	sja1105_packing(buf, &entry->vlmask,      106,  75, size, op);
	sja1105_packing(buf, &entry->tpid2,        74,  59, size, op);
	sja1105_packing(buf, &entry->ignore2stf,   58,  58, size, op);
	sja1105_packing(buf, &entry->tpid,         57,  42, size, op);
	sja1105_packing(buf, &entry->queue_ts,     41,  41, size, op);
	sja1105_packing(buf, &entry->egrmirrvid,   40,  29, size, op);
	sja1105_packing(buf, &entry->egrmirrpcp,   28,  26, size, op);
	sja1105_packing(buf, &entry->egrmirrdei,   25,  25, size, op);
	sja1105_packing(buf, &entry->replay_port,  24,  22, size, op);
	return size;
}

size_t sja1110_general_params_entry_packing(void *buf, void *entry_ptr,
					    enum packing_op op)
{
	struct sja1105_general_params_entry *entry = entry_ptr;
	const size_t size = SJA1110_SIZE_GENERAL_PARAMS_ENTRY;

	sja1105_packing(buf, &entry->vllupformat,  447, 447, size, op);
	sja1105_packing(buf, &entry->mirr_ptacu,   446, 446, size, op);
	sja1105_packing(buf, &entry->switchid,     445, 442, size, op);
	sja1105_packing(buf, &entry->hostprio,     441, 439, size, op);
	sja1105_packing(buf, &entry->mac_fltres1,  438, 391, size, op);
	sja1105_packing(buf, &entry->mac_fltres0,  390, 343, size, op);
	sja1105_packing(buf, &entry->mac_flt1,     342, 295, size, op);
	sja1105_packing(buf, &entry->mac_flt0,     294, 247, size, op);
	sja1105_packing(buf, &entry->incl_srcpt1,  246, 246, size, op);
	sja1105_packing(buf, &entry->incl_srcpt0,  245, 245, size, op);
	sja1105_packing(buf, &entry->send_meta1,   244, 244, size, op);
	sja1105_packing(buf, &entry->send_meta0,   243, 243, size, op);
	sja1105_packing(buf, &entry->casc_port,    242, 232, size, op);
	sja1105_packing(buf, &entry->host_port,    231, 228, size, op);
	sja1105_packing(buf, &entry->mirr_port,    227, 224, size, op);
	sja1105_packing(buf, &entry->vlmarker,     223, 192, size, op);
	sja1105_packing(buf, &entry->vlmask,       191, 160, size, op);
	sja1105_packing(buf, &entry->tpid2,        159, 144, size, op);
	sja1105_packing(buf, &entry->ignore2stf,   143, 143, size, op);
	sja1105_packing(buf, &entry->tpid,         142, 127, size, op);
	sja1105_packing(buf, &entry->queue_ts,     126, 126, size, op);
	sja1105_packing(buf, &entry->egrmirrvid,   125, 114, size, op);
	sja1105_packing(buf, &entry->egrmirrpcp,   113, 111, size, op);
	sja1105_packing(buf, &entry->egrmirrdei,   110, 110, size, op);
	sja1105_packing(buf, &entry->replay_port,  109, 106, size, op);
	sja1105_packing(buf, &entry->tdmaconfigidx, 70,  67, size, op);
	sja1105_packing(buf, &entry->header_type,   64,  49, size, op);
	sja1105_packing(buf, &entry->ts_threshold,  48,  44, size, op);
	sja1105_packing(buf, &entry->ts_timeout,    43,  30, size, op);
	sja1105_packing(buf, &entry->tte_en,        16,  16, size, op);
	return size;
}

static size_t
sja1105_l2_forwarding_params_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	const size_t size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY;
	struct sja1105_l2_forwarding_params_entry *entry = entry_ptr;
	int offset, i;

	sja1105_packing(buf, &entry->max_dynp, 95, 93, size, op);
	for (i = 0, offset = 13; i < 8; i++, offset += 10)
		sja1105_packing(buf, &entry->part_spc[i],
				offset + 9, offset + 0, size, op);
	return size;
}

size_t sja1110_l2_forwarding_params_entry_packing(void *buf, void *entry_ptr,
						  enum packing_op op)
{
	struct sja1105_l2_forwarding_params_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY;
	int offset, i;

	sja1105_packing(buf, &entry->max_dynp, 95, 93, size, op);
	for (i = 0, offset = 5; i < 8; i++, offset += 11)
		sja1105_packing(buf, &entry->part_spc[i],
				offset + 10, offset + 0, size, op);
	return size;
}

size_t sja1105_l2_forwarding_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	const size_t size = SJA1105_SIZE_L2_FORWARDING_ENTRY;
	struct sja1105_l2_forwarding_entry *entry = entry_ptr;
	int offset, i;

	sja1105_packing(buf, &entry->bc_domain,  63, 59, size, op);
	sja1105_packing(buf, &entry->reach_port, 58, 54, size, op);
	sja1105_packing(buf, &entry->fl_domain,  53, 49, size, op);
	for (i = 0, offset = 25; i < 8; i++, offset += 3)
		sja1105_packing(buf, &entry->vlan_pmap[i],
				offset + 2, offset + 0, size, op);
	return size;
}

size_t sja1110_l2_forwarding_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	struct sja1105_l2_forwarding_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_L2_FORWARDING_ENTRY;
	int offset, i;

	if (entry->type_egrpcp2outputq) {
		for (i = 0, offset = 31; i < SJA1110_NUM_PORTS;
		     i++, offset += 3) {
			sja1105_packing(buf, &entry->vlan_pmap[i],
					offset + 2, offset + 0, size, op);
		}
	} else {
		sja1105_packing(buf, &entry->bc_domain,  63, 53, size, op);
		sja1105_packing(buf, &entry->reach_port, 52, 42, size, op);
		sja1105_packing(buf, &entry->fl_domain,  41, 31, size, op);
	}
	return size;
}

static size_t
sja1105et_l2_lookup_params_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	const size_t size = SJA1105ET_SIZE_L2_LOOKUP_PARAMS_ENTRY;
	struct sja1105_l2_lookup_params_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->maxage,         31, 17, size, op);
	sja1105_packing(buf, &entry->dyn_tbsz,       16, 14, size, op);
	sja1105_packing(buf, &entry->poly,           13,  6, size, op);
	sja1105_packing(buf, &entry->shared_learn,    5,  5, size, op);
	sja1105_packing(buf, &entry->no_enf_hostprt,  4,  4, size, op);
	sja1105_packing(buf, &entry->no_mgmt_learn,   3,  3, size, op);
	return size;
}

size_t sja1105pqrs_l2_lookup_params_entry_packing(void *buf, void *entry_ptr,
						  enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_L2_LOOKUP_PARAMS_ENTRY;
	struct sja1105_l2_lookup_params_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 58; i < 5; i++, offset += 11)
		sja1105_packing(buf, &entry->maxaddrp[i],
				offset + 10, offset + 0, size, op);
	sja1105_packing(buf, &entry->maxage,         57,  43, size, op);
	sja1105_packing(buf, &entry->start_dynspc,   42,  33, size, op);
	sja1105_packing(buf, &entry->drpnolearn,     32,  28, size, op);
	sja1105_packing(buf, &entry->shared_learn,   27,  27, size, op);
	sja1105_packing(buf, &entry->no_enf_hostprt, 26,  26, size, op);
	sja1105_packing(buf, &entry->no_mgmt_learn,  25,  25, size, op);
	sja1105_packing(buf, &entry->use_static,     24,  24, size, op);
	sja1105_packing(buf, &entry->owr_dyn,        23,  23, size, op);
	sja1105_packing(buf, &entry->learn_once,     22,  22, size, op);
	return size;
}

size_t sja1110_l2_lookup_params_entry_packing(void *buf, void *entry_ptr,
					      enum packing_op op)
{
	struct sja1105_l2_lookup_params_entry *entry = entry_ptr;
	const size_t size = SJA1110_SIZE_L2_LOOKUP_PARAMS_ENTRY;
	int offset, i;

	for (i = 0, offset = 70; i < SJA1110_NUM_PORTS; i++, offset += 11)
		sja1105_packing(buf, &entry->maxaddrp[i],
				offset + 10, offset + 0, size, op);
	sja1105_packing(buf, &entry->maxage,         69,  55, size, op);
	sja1105_packing(buf, &entry->start_dynspc,   54,  45, size, op);
	sja1105_packing(buf, &entry->drpnolearn,     44,  34, size, op);
	sja1105_packing(buf, &entry->shared_learn,   33,  33, size, op);
	sja1105_packing(buf, &entry->no_enf_hostprt, 32,  32, size, op);
	sja1105_packing(buf, &entry->no_mgmt_learn,  31,  31, size, op);
	sja1105_packing(buf, &entry->use_static,     30,  30, size, op);
	sja1105_packing(buf, &entry->owr_dyn,        29,  29, size, op);
	sja1105_packing(buf, &entry->learn_once,     28,  28, size, op);
	return size;
}

size_t sja1105et_l2_lookup_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	const size_t size = SJA1105ET_SIZE_L2_LOOKUP_ENTRY;
	struct sja1105_l2_lookup_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->vlanid,    95, 84, size, op);
	sja1105_packing(buf, &entry->macaddr,   83, 36, size, op);
	sja1105_packing(buf, &entry->destports, 35, 31, size, op);
	sja1105_packing(buf, &entry->enfport,   30, 30, size, op);
	sja1105_packing(buf, &entry->index,     29, 20, size, op);
	return size;
}

size_t sja1105pqrs_l2_lookup_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_L2_LOOKUP_ENTRY;
	struct sja1105_l2_lookup_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->tsreg,        159, 159, size, op);
	sja1105_packing(buf, &entry->mirrvlan,     158, 147, size, op);
	sja1105_packing(buf, &entry->takets,       146, 146, size, op);
	sja1105_packing(buf, &entry->mirr,         145, 145, size, op);
	sja1105_packing(buf, &entry->retag,        144, 144, size, op);
	sja1105_packing(buf, &entry->mask_iotag,   143, 143, size, op);
	sja1105_packing(buf, &entry->mask_vlanid,  142, 131, size, op);
	sja1105_packing(buf, &entry->mask_macaddr, 130,  83, size, op);
	sja1105_packing(buf, &entry->iotag,         82,  82, size, op);
	sja1105_packing(buf, &entry->vlanid,        81,  70, size, op);
	sja1105_packing(buf, &entry->macaddr,       69,  22, size, op);
	sja1105_packing(buf, &entry->destports,     21,  17, size, op);
	sja1105_packing(buf, &entry->enfport,       16,  16, size, op);
	sja1105_packing(buf, &entry->index,         15,   6, size, op);
	return size;
}

size_t sja1110_l2_lookup_entry_packing(void *buf, void *entry_ptr,
				       enum packing_op op)
{
	const size_t size = SJA1110_SIZE_L2_LOOKUP_ENTRY;
	struct sja1105_l2_lookup_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->trap,         168, 168, size, op);
	sja1105_packing(buf, &entry->mirrvlan,     167, 156, size, op);
	sja1105_packing(buf, &entry->takets,       155, 155, size, op);
	sja1105_packing(buf, &entry->mirr,         154, 154, size, op);
	sja1105_packing(buf, &entry->retag,        153, 153, size, op);
	sja1105_packing(buf, &entry->mask_iotag,   152, 152, size, op);
	sja1105_packing(buf, &entry->mask_vlanid,  151, 140, size, op);
	sja1105_packing(buf, &entry->mask_macaddr, 139,  92, size, op);
	sja1105_packing(buf, &entry->mask_srcport,  91,  88, size, op);
	sja1105_packing(buf, &entry->iotag,         87,  87, size, op);
	sja1105_packing(buf, &entry->vlanid,        86,  75, size, op);
	sja1105_packing(buf, &entry->macaddr,       74,  27, size, op);
	sja1105_packing(buf, &entry->srcport,       26,  23, size, op);
	sja1105_packing(buf, &entry->destports,     22,  12, size, op);
	sja1105_packing(buf, &entry->enfport,       11,  11, size, op);
	sja1105_packing(buf, &entry->index,         10,   1, size, op);
	return size;
}

static size_t sja1105_l2_policing_entry_packing(void *buf, void *entry_ptr,
						enum packing_op op)
{
	const size_t size = SJA1105_SIZE_L2_POLICING_ENTRY;
	struct sja1105_l2_policing_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->sharindx,  63, 58, size, op);
	sja1105_packing(buf, &entry->smax,      57, 42, size, op);
	sja1105_packing(buf, &entry->rate,      41, 26, size, op);
	sja1105_packing(buf, &entry->maxlen,    25, 15, size, op);
	sja1105_packing(buf, &entry->partition, 14, 12, size, op);
	return size;
}

size_t sja1110_l2_policing_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	struct sja1105_l2_policing_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_L2_POLICING_ENTRY;

	sja1105_packing(buf, &entry->sharindx, 63, 57, size, op);
	sja1105_packing(buf, &entry->smax,     56, 39, size, op);
	sja1105_packing(buf, &entry->rate,     38, 21, size, op);
	sja1105_packing(buf, &entry->maxlen,   20, 10, size, op);
	sja1105_packing(buf, &entry->partition, 9,  7, size, op);
	return size;
}

static size_t sja1105et_mac_config_entry_packing(void *buf, void *entry_ptr,
						 enum packing_op op)
{
	const size_t size = SJA1105ET_SIZE_MAC_CONFIG_ENTRY;
	struct sja1105_mac_config_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 72; i < 8; i++, offset += 19) {
		sja1105_packing(buf, &entry->enabled[i],
				offset +  0, offset +  0, size, op);
		sja1105_packing(buf, &entry->base[i],
				offset +  9, offset +  1, size, op);
		sja1105_packing(buf, &entry->top[i],
				offset + 18, offset + 10, size, op);
	}
	sja1105_packing(buf, &entry->ifg,       71, 67, size, op);
	sja1105_packing(buf, &entry->speed,     66, 65, size, op);
	sja1105_packing(buf, &entry->tp_delin,  64, 49, size, op);
	sja1105_packing(buf, &entry->tp_delout, 48, 33, size, op);
	sja1105_packing(buf, &entry->maxage,    32, 25, size, op);
	sja1105_packing(buf, &entry->vlanprio,  24, 22, size, op);
	sja1105_packing(buf, &entry->vlanid,    21, 10, size, op);
	sja1105_packing(buf, &entry->ing_mirr,   9,  9, size, op);
	sja1105_packing(buf, &entry->egr_mirr,   8,  8, size, op);
	sja1105_packing(buf, &entry->drpnona664, 7,  7, size, op);
	sja1105_packing(buf, &entry->drpdtag,    6,  6, size, op);
	sja1105_packing(buf, &entry->drpuntag,   5,  5, size, op);
	sja1105_packing(buf, &entry->retag,      4,  4, size, op);
	sja1105_packing(buf, &entry->dyn_learn,  3,  3, size, op);
	sja1105_packing(buf, &entry->egress,     2,  2, size, op);
	sja1105_packing(buf, &entry->ingress,    1,  1, size, op);
	return size;
}

size_t sja1105pqrs_mac_config_entry_packing(void *buf, void *entry_ptr,
					    enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY;
	struct sja1105_mac_config_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 104; i < 8; i++, offset += 19) {
		sja1105_packing(buf, &entry->enabled[i],
				offset +  0, offset +  0, size, op);
		sja1105_packing(buf, &entry->base[i],
				offset +  9, offset +  1, size, op);
		sja1105_packing(buf, &entry->top[i],
				offset + 18, offset + 10, size, op);
	}
	sja1105_packing(buf, &entry->ifg,       103, 99, size, op);
	sja1105_packing(buf, &entry->speed,      98, 97, size, op);
	sja1105_packing(buf, &entry->tp_delin,   96, 81, size, op);
	sja1105_packing(buf, &entry->tp_delout,  80, 65, size, op);
	sja1105_packing(buf, &entry->maxage,     64, 57, size, op);
	sja1105_packing(buf, &entry->vlanprio,   56, 54, size, op);
	sja1105_packing(buf, &entry->vlanid,     53, 42, size, op);
	sja1105_packing(buf, &entry->ing_mirr,   41, 41, size, op);
	sja1105_packing(buf, &entry->egr_mirr,   40, 40, size, op);
	sja1105_packing(buf, &entry->drpnona664, 39, 39, size, op);
	sja1105_packing(buf, &entry->drpdtag,    38, 38, size, op);
	sja1105_packing(buf, &entry->drpuntag,   35, 35, size, op);
	sja1105_packing(buf, &entry->retag,      34, 34, size, op);
	sja1105_packing(buf, &entry->dyn_learn,  33, 33, size, op);
	sja1105_packing(buf, &entry->egress,     32, 32, size, op);
	sja1105_packing(buf, &entry->ingress,    31, 31, size, op);
	return size;
}

size_t sja1110_mac_config_entry_packing(void *buf, void *entry_ptr,
					enum packing_op op)
{
	const size_t size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY;
	struct sja1105_mac_config_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 104; i < 8; i++, offset += 19) {
		sja1105_packing(buf, &entry->enabled[i],
				offset +  0, offset +  0, size, op);
		sja1105_packing(buf, &entry->base[i],
				offset +  9, offset +  1, size, op);
		sja1105_packing(buf, &entry->top[i],
				offset + 18, offset + 10, size, op);
	}
	sja1105_packing(buf, &entry->speed,      98, 96, size, op);
	sja1105_packing(buf, &entry->tp_delin,   95, 80, size, op);
	sja1105_packing(buf, &entry->tp_delout,  79, 64, size, op);
	sja1105_packing(buf, &entry->maxage,     63, 56, size, op);
	sja1105_packing(buf, &entry->vlanprio,   55, 53, size, op);
	sja1105_packing(buf, &entry->vlanid,     52, 41, size, op);
	sja1105_packing(buf, &entry->ing_mirr,   40, 40, size, op);
	sja1105_packing(buf, &entry->egr_mirr,   39, 39, size, op);
	sja1105_packing(buf, &entry->drpnona664, 38, 38, size, op);
	sja1105_packing(buf, &entry->drpdtag,    37, 37, size, op);
	sja1105_packing(buf, &entry->drpuntag,   34, 34, size, op);
	sja1105_packing(buf, &entry->retag,      33, 33, size, op);
	sja1105_packing(buf, &entry->dyn_learn,  32, 32, size, op);
	sja1105_packing(buf, &entry->egress,     31, 31, size, op);
	sja1105_packing(buf, &entry->ingress,    30, 30, size, op);
	sja1105_packing(buf, &entry->ifg,        10,  5, size, op);
	return size;
}

static size_t
sja1105_schedule_entry_points_params_entry_packing(void *buf, void *entry_ptr,
						   enum packing_op op)
{
	struct sja1105_schedule_entry_points_params_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_PARAMS_ENTRY;

	sja1105_packing(buf, &entry->clksrc,    31, 30, size, op);
	sja1105_packing(buf, &entry->actsubsch, 29, 27, size, op);
	return size;
}

static size_t
sja1105_schedule_entry_points_entry_packing(void *buf, void *entry_ptr,
					    enum packing_op op)
{
	struct sja1105_schedule_entry_points_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY;

	sja1105_packing(buf, &entry->subschindx, 31, 29, size, op);
	sja1105_packing(buf, &entry->delta,      28, 11, size, op);
	sja1105_packing(buf, &entry->address,    10, 1,  size, op);
	return size;
}

static size_t
sja1110_schedule_entry_points_entry_packing(void *buf, void *entry_ptr,
					    enum packing_op op)
{
	struct sja1105_schedule_entry_points_entry *entry = entry_ptr;
	const size_t size = SJA1110_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY;

	sja1105_packing(buf, &entry->subschindx, 63, 61, size, op);
	sja1105_packing(buf, &entry->delta,      60, 43, size, op);
	sja1105_packing(buf, &entry->address,    42, 31, size, op);
	return size;
}

static size_t sja1105_schedule_params_entry_packing(void *buf, void *entry_ptr,
						    enum packing_op op)
{
	const size_t size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY;
	struct sja1105_schedule_params_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 16; i < 8; i++, offset += 10)
		sja1105_packing(buf, &entry->subscheind[i],
				offset + 9, offset + 0, size, op);
	return size;
}

static size_t sja1110_schedule_params_entry_packing(void *buf, void *entry_ptr,
						    enum packing_op op)
{
	struct sja1105_schedule_params_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY;
	int offset, i;

	for (i = 0, offset = 0; i < 8; i++, offset += 12)
		sja1105_packing(buf, &entry->subscheind[i],
				offset + 11, offset + 0, size, op);
	return size;
}

static size_t sja1105_schedule_entry_packing(void *buf, void *entry_ptr,
					     enum packing_op op)
{
	const size_t size = SJA1105_SIZE_SCHEDULE_ENTRY;
	struct sja1105_schedule_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->winstindex,  63, 54, size, op);
	sja1105_packing(buf, &entry->winend,      53, 53, size, op);
	sja1105_packing(buf, &entry->winst,       52, 52, size, op);
	sja1105_packing(buf, &entry->destports,   51, 47, size, op);
	sja1105_packing(buf, &entry->setvalid,    46, 46, size, op);
	sja1105_packing(buf, &entry->txen,        45, 45, size, op);
	sja1105_packing(buf, &entry->resmedia_en, 44, 44, size, op);
	sja1105_packing(buf, &entry->resmedia,    43, 36, size, op);
	sja1105_packing(buf, &entry->vlindex,     35, 26, size, op);
	sja1105_packing(buf, &entry->delta,       25, 8,  size, op);
	return size;
}

static size_t sja1110_schedule_entry_packing(void *buf, void *entry_ptr,
					     enum packing_op op)
{
	const size_t size = SJA1110_SIZE_SCHEDULE_ENTRY;
	struct sja1105_schedule_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->winstindex,  95, 84, size, op);
	sja1105_packing(buf, &entry->winend,      83, 83, size, op);
	sja1105_packing(buf, &entry->winst,       82, 82, size, op);
	sja1105_packing(buf, &entry->destports,   81, 71, size, op);
	sja1105_packing(buf, &entry->setvalid,    70, 70, size, op);
	sja1105_packing(buf, &entry->txen,        69, 69, size, op);
	sja1105_packing(buf, &entry->resmedia_en, 68, 68, size, op);
	sja1105_packing(buf, &entry->resmedia,    67, 60, size, op);
	sja1105_packing(buf, &entry->vlindex,     59, 48, size, op);
	sja1105_packing(buf, &entry->delta,       47, 30, size, op);
	return size;
}

static size_t
sja1105_vl_forwarding_params_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	struct sja1105_vl_forwarding_params_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY;
	int offset, i;

	for (i = 0, offset = 16; i < 8; i++, offset += 10)
		sja1105_packing(buf, &entry->partspc[i],
				offset + 9, offset + 0, size, op);
	sja1105_packing(buf, &entry->debugen, 15, 15, size, op);
	return size;
}

static size_t
sja1110_vl_forwarding_params_entry_packing(void *buf, void *entry_ptr,
					   enum packing_op op)
{
	struct sja1105_vl_forwarding_params_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY;
	int offset, i;

	for (i = 0, offset = 8; i < 8; i++, offset += 11)
		sja1105_packing(buf, &entry->partspc[i],
				offset + 10, offset + 0, size, op);
	sja1105_packing(buf, &entry->debugen, 7, 7, size, op);
	return size;
}

static size_t sja1105_vl_forwarding_entry_packing(void *buf, void *entry_ptr,
						  enum packing_op op)
{
	struct sja1105_vl_forwarding_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_FORWARDING_ENTRY;

	sja1105_packing(buf, &entry->type,      31, 31, size, op);
	sja1105_packing(buf, &entry->priority,  30, 28, size, op);
	sja1105_packing(buf, &entry->partition, 27, 25, size, op);
	sja1105_packing(buf, &entry->destports, 24, 20, size, op);
	return size;
}

static size_t sja1110_vl_forwarding_entry_packing(void *buf, void *entry_ptr,
						  enum packing_op op)
{
	struct sja1105_vl_forwarding_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_FORWARDING_ENTRY;

	sja1105_packing(buf, &entry->type,      31, 31, size, op);
	sja1105_packing(buf, &entry->priority,  30, 28, size, op);
	sja1105_packing(buf, &entry->partition, 27, 25, size, op);
	sja1105_packing(buf, &entry->destports, 24, 14, size, op);
	return size;
}

size_t sja1105_vl_lookup_entry_packing(void *buf, void *entry_ptr,
				       enum packing_op op)
{
	struct sja1105_vl_lookup_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_LOOKUP_ENTRY;

	if (entry->format == SJA1105_VL_FORMAT_PSFP) {
		/* Interpreting vllupformat as 0 */
		sja1105_packing(buf, &entry->destports,
				95, 91, size, op);
		sja1105_packing(buf, &entry->iscritical,
				90, 90, size, op);
		sja1105_packing(buf, &entry->macaddr,
				89, 42, size, op);
		sja1105_packing(buf, &entry->vlanid,
				41, 30, size, op);
		sja1105_packing(buf, &entry->port,
				29, 27, size, op);
		sja1105_packing(buf, &entry->vlanprior,
				26, 24, size, op);
	} else {
		/* Interpreting vllupformat as 1 */
		sja1105_packing(buf, &entry->egrmirr,
				95, 91, size, op);
		sja1105_packing(buf, &entry->ingrmirr,
				90, 90, size, op);
		sja1105_packing(buf, &entry->vlid,
				57, 42, size, op);
		sja1105_packing(buf, &entry->port,
				29, 27, size, op);
	}
	return size;
}

size_t sja1110_vl_lookup_entry_packing(void *buf, void *entry_ptr,
				       enum packing_op op)
{
	struct sja1105_vl_lookup_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_LOOKUP_ENTRY;

	if (entry->format == SJA1105_VL_FORMAT_PSFP) {
		/* Interpreting vllupformat as 0 */
		/* XXX: vl_police ? */
		sja1105_packing(buf, &entry->destports,
				94, 84, size, op);
		sja1105_packing(buf, &entry->iscritical,
				83, 83, size, op);
		sja1105_packing(buf, &entry->macaddr,
				82, 35, size, op);
		sja1105_packing(buf, &entry->vlanid,
				34, 23, size, op);
		sja1105_packing(buf, &entry->port,
				22, 19, size, op);
		sja1105_packing(buf, &entry->vlanprior,
				18, 16, size, op);
	} else {
		/* Interpreting vllupformat as 1 */
		sja1105_packing(buf, &entry->egrmirr,
				94, 84, size, op);
		sja1105_packing(buf, &entry->ingrmirr,
				83, 83, size, op);
		sja1105_packing(buf, &entry->vlid,
				50, 35, size, op);
		sja1105_packing(buf, &entry->port,
				22, 19, size, op);
	}
	return size;
}

static size_t sja1105_vl_policing_entry_packing(void *buf, void *entry_ptr,
						enum packing_op op)
{
	struct sja1105_vl_policing_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_POLICING_ENTRY;

	sja1105_packing(buf, &entry->type,      63, 63, size, op);
	sja1105_packing(buf, &entry->maxlen,    62, 52, size, op);
	sja1105_packing(buf, &entry->sharindx,  51, 42, size, op);
	if (entry->type == 0) {
		sja1105_packing(buf, &entry->bag,    41, 28, size, op);
		sja1105_packing(buf, &entry->jitter, 27, 18, size, op);
	}
	return size;
}

size_t sja1110_vl_policing_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	struct sja1105_vl_policing_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_VL_POLICING_ENTRY;

	sja1105_packing(buf, &entry->type,      63, 63, size, op);
	sja1105_packing(buf, &entry->maxlen,    62, 52, size, op);
	sja1105_packing(buf, &entry->sharindx,  51, 40, size, op);
	if (entry->type == 0) {
		sja1105_packing(buf, &entry->bag,    41, 28, size, op);
		sja1105_packing(buf, &entry->jitter, 27, 18, size, op);
	}
	return size;
}

size_t sja1105_vlan_lookup_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	const size_t size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY;
	struct sja1105_vlan_lookup_entry *entry = entry_ptr;

	sja1105_packing(buf, &entry->ving_mirr,  63, 59, size, op);
	sja1105_packing(buf, &entry->vegr_mirr,  58, 54, size, op);
	sja1105_packing(buf, &entry->vmemb_port, 53, 49, size, op);
	sja1105_packing(buf, &entry->vlan_bc,    48, 44, size, op);
	sja1105_packing(buf, &entry->tag_port,   43, 39, size, op);
	sja1105_packing(buf, &entry->vlanid,     38, 27, size, op);
	return size;
}

size_t sja1110_vlan_lookup_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	struct sja1105_vlan_lookup_entry *entry = entry_ptr;
	const size_t size = SJA1110_SIZE_VLAN_LOOKUP_ENTRY;

	sja1105_packing(buf, &entry->ving_mirr,  95, 85, size, op);
	sja1105_packing(buf, &entry->vegr_mirr,  84, 74, size, op);
	sja1105_packing(buf, &entry->vmemb_port, 73, 63, size, op);
	sja1105_packing(buf, &entry->vlan_bc,    62, 52, size, op);
	sja1105_packing(buf, &entry->tag_port,   51, 41, size, op);
	sja1105_packing(buf, &entry->type_entry, 40, 39, size, op);
	sja1105_packing(buf, &entry->vlanid,     38, 27, size, op);
	return size;
}

static size_t sja1105_xmii_params_entry_packing(void *buf, void *entry_ptr,
						enum packing_op op)
{
	const size_t size = SJA1105_SIZE_XMII_PARAMS_ENTRY;
	struct sja1105_xmii_params_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 17; i < 5; i++, offset += 3) {
		sja1105_packing(buf, &entry->xmii_mode[i],
				offset + 1, offset + 0, size, op);
		sja1105_packing(buf, &entry->phy_mac[i],
				offset + 2, offset + 2, size, op);
	}
	return size;
}

size_t sja1110_xmii_params_entry_packing(void *buf, void *entry_ptr,
					 enum packing_op op)
{
	const size_t size = SJA1110_SIZE_XMII_PARAMS_ENTRY;
	struct sja1105_xmii_params_entry *entry = entry_ptr;
	int offset, i;

	for (i = 0, offset = 20; i < SJA1110_NUM_PORTS; i++, offset += 4) {
		sja1105_packing(buf, &entry->xmii_mode[i],
				offset + 1, offset + 0, size, op);
		sja1105_packing(buf, &entry->phy_mac[i],
				offset + 2, offset + 2, size, op);
		sja1105_packing(buf, &entry->special[i],
				offset + 3, offset + 3, size, op);
	}
	return size;
}

size_t sja1105_retagging_entry_packing(void *buf, void *entry_ptr,
				       enum packing_op op)
{
	struct sja1105_retagging_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_RETAGGING_ENTRY;

	sja1105_packing(buf, &entry->egr_port,       63, 59, size, op);
	sja1105_packing(buf, &entry->ing_port,       58, 54, size, op);
	sja1105_packing(buf, &entry->vlan_ing,       53, 42, size, op);
	sja1105_packing(buf, &entry->vlan_egr,       41, 30, size, op);
	sja1105_packing(buf, &entry->do_not_learn,   29, 29, size, op);
	sja1105_packing(buf, &entry->use_dest_ports, 28, 28, size, op);
	sja1105_packing(buf, &entry->destports,      27, 23, size, op);
	return size;
}

size_t sja1110_retagging_entry_packing(void *buf, void *entry_ptr,
				       enum packing_op op)
{
	struct sja1105_retagging_entry *entry = entry_ptr;
	const size_t size = SJA1105_SIZE_RETAGGING_ENTRY;

	sja1105_packing(buf, &entry->egr_port,       63, 53, size, op);
	sja1105_packing(buf, &entry->ing_port,       52, 42, size, op);
	sja1105_packing(buf, &entry->vlan_ing,       41, 30, size, op);
	sja1105_packing(buf, &entry->vlan_egr,       29, 18, size, op);
	sja1105_packing(buf, &entry->do_not_learn,   17, 17, size, op);
	sja1105_packing(buf, &entry->use_dest_ports, 16, 16, size, op);
	sja1105_packing(buf, &entry->destports,      15, 5, size, op);
	return size;
}

static size_t sja1110_pcp_remapping_entry_packing(void *buf, void *entry_ptr,
						  enum packing_op op)
{
	struct sja1110_pcp_remapping_entry *entry = entry_ptr;
	const size_t size = SJA1110_SIZE_PCP_REMAPPING_ENTRY;
	int offset, i;

	for (i = 0, offset = 8; i < SJA1105_NUM_TC; i++, offset += 3)
		sja1105_packing(buf, &entry->egrpcp[i],
				offset + 2, offset + 0, size, op);

	return size;
}

size_t sja1105_table_header_packing(void *buf, void *entry_ptr,
				    enum packing_op op)
{
	const size_t size = SJA1105_SIZE_TABLE_HEADER;
	struct sja1105_table_header *entry = entry_ptr;

	sja1105_packing(buf, &entry->block_id, 31, 24, size, op);
	sja1105_packing(buf, &entry->len,      55, 32, size, op);
	sja1105_packing(buf, &entry->crc,      95, 64, size, op);
	return size;
}

/* WARNING: the *hdr pointer is really non-const, because it is
 * modifying the CRC of the header for a 2-stage packing operation
 */
void
sja1105_table_header_pack_with_crc(void *buf, struct sja1105_table_header *hdr)
{
	/* First pack the table as-is, then calculate the CRC, and
	 * finally put the proper CRC into the packed buffer
	 */
	memset(buf, 0, SJA1105_SIZE_TABLE_HEADER);
	sja1105_table_header_packing(buf, hdr, PACK);
	hdr->crc = sja1105_crc32(buf, SJA1105_SIZE_TABLE_HEADER - 4);
	sja1105_packing(buf + SJA1105_SIZE_TABLE_HEADER - 4, &hdr->crc,
			31, 0, 4, PACK);
}

static void sja1105_table_write_crc(u8 *table_start, u8 *crc_ptr)
{
	u64 computed_crc;
	int len_bytes;

	len_bytes = (uintptr_t)(crc_ptr - table_start);
	computed_crc = sja1105_crc32(table_start, len_bytes);
	sja1105_packing(crc_ptr, &computed_crc, 31, 0, 4, PACK);
}

/* The block IDs that the switches support are unfortunately sparse, so keep a
 * mapping table to "block indices" and translate back and forth so that we
 * don't waste useless memory in struct sja1105_static_config.
 * Also, since the block id comes from essentially untrusted input (unpacking
 * the static config from userspace) it has to be sanitized (range-checked)
 * before blindly indexing kernel memory with the blk_idx.
 */
static u64 blk_id_map[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = BLKID_SCHEDULE,
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = BLKID_SCHEDULE_ENTRY_POINTS,
	[BLK_IDX_VL_LOOKUP] = BLKID_VL_LOOKUP,
	[BLK_IDX_VL_POLICING] = BLKID_VL_POLICING,
	[BLK_IDX_VL_FORWARDING] = BLKID_VL_FORWARDING,
	[BLK_IDX_L2_LOOKUP] = BLKID_L2_LOOKUP,
	[BLK_IDX_L2_POLICING] = BLKID_L2_POLICING,
	[BLK_IDX_VLAN_LOOKUP] = BLKID_VLAN_LOOKUP,
	[BLK_IDX_L2_FORWARDING] = BLKID_L2_FORWARDING,
	[BLK_IDX_MAC_CONFIG] = BLKID_MAC_CONFIG,
	[BLK_IDX_SCHEDULE_PARAMS] = BLKID_SCHEDULE_PARAMS,
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = BLKID_SCHEDULE_ENTRY_POINTS_PARAMS,
	[BLK_IDX_VL_FORWARDING_PARAMS] = BLKID_VL_FORWARDING_PARAMS,
	[BLK_IDX_L2_LOOKUP_PARAMS] = BLKID_L2_LOOKUP_PARAMS,
	[BLK_IDX_L2_FORWARDING_PARAMS] = BLKID_L2_FORWARDING_PARAMS,
	[BLK_IDX_AVB_PARAMS] = BLKID_AVB_PARAMS,
	[BLK_IDX_GENERAL_PARAMS] = BLKID_GENERAL_PARAMS,
	[BLK_IDX_RETAGGING] = BLKID_RETAGGING,
	[BLK_IDX_XMII_PARAMS] = BLKID_XMII_PARAMS,
	[BLK_IDX_PCP_REMAPPING] = BLKID_PCP_REMAPPING,
};

static enum sja1105_blk_idx blk_idx_from_blk_id(u64 block_id)
{
	enum sja1105_blk_idx blk_idx;

	if (block_id > BLKID_MAX)
		return BLK_IDX_INVAL;

	for (blk_idx = 0; blk_idx < BLK_IDX_MAX; blk_idx++)
		if (blk_id_map[blk_idx] == block_id)
			return blk_idx;

	return BLK_IDX_INVAL;
}

static ssize_t
sja1105_table_add_entry(struct sja1105_table *table, const void *buf)
{
	void *entry_ptr;

	if (table->entry_count >= table->ops->max_entry_count)
		return -ERANGE;

	entry_ptr = table->entries;
	entry_ptr += (uintptr_t)table->ops->unpacked_entry_size *
				table->entry_count;

	table->entry_count++;

	memset(entry_ptr, 0, table->ops->unpacked_entry_size);

	/* Discard const pointer due to common implementation
	 * of PACK and UNPACK.
	 */
	return table->ops->packing((void *)buf, entry_ptr, UNPACK);
}

/* Compatibility matrices */

/* SJA1105E: First generation, no TTEthernet */
static const struct sja1105_table_ops sja1105e_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105et_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105ET_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105et_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105ET_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105et_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105et_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105et_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1105T: First generation, TTEthernet */
static const struct sja1105_table_ops sja1105t_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = {
		.packing = sja1105_schedule_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = {
		.packing = sja1105_schedule_entry_points_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_COUNT,
	},
	[BLK_IDX_VL_LOOKUP] = {
		.packing = sja1105_vl_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VL_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_LOOKUP_COUNT,
	},
	[BLK_IDX_VL_POLICING] = {
		.packing = sja1105_vl_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_policing_entry),
		.packed_entry_size = SJA1105_SIZE_VL_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_POLICING_COUNT,
	},
	[BLK_IDX_VL_FORWARDING] = {
		.packing = sja1105_vl_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_COUNT,
	},
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105et_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105ET_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105et_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105ET_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_SCHEDULE_PARAMS] = {
		.packing = sja1105_schedule_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_PARAMS_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = {
		.packing = sja1105_schedule_entry_points_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_PARAMS_COUNT,
	},
	[BLK_IDX_VL_FORWARDING_PARAMS] = {
		.packing = sja1105_vl_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105et_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105et_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105et_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105ET_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1105P: Second generation, no TTEthernet, no SGMII */
static const struct sja1105_table_ops sja1105p_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105pqrs_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105pqrs_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105pqrs_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105pqrs_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105pqrs_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1105Q: Second generation, TTEthernet, no SGMII */
static const struct sja1105_table_ops sja1105q_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = {
		.packing = sja1105_schedule_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = {
		.packing = sja1105_schedule_entry_points_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_COUNT,
	},
	[BLK_IDX_VL_LOOKUP] = {
		.packing = sja1105_vl_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VL_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_LOOKUP_COUNT,
	},
	[BLK_IDX_VL_POLICING] = {
		.packing = sja1105_vl_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_policing_entry),
		.packed_entry_size = SJA1105_SIZE_VL_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_POLICING_COUNT,
	},
	[BLK_IDX_VL_FORWARDING] = {
		.packing = sja1105_vl_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_COUNT,
	},
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105pqrs_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105pqrs_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_SCHEDULE_PARAMS] = {
		.packing = sja1105_schedule_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_PARAMS_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = {
		.packing = sja1105_schedule_entry_points_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_PARAMS_COUNT,
	},
	[BLK_IDX_VL_FORWARDING_PARAMS] = {
		.packing = sja1105_vl_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105pqrs_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105pqrs_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105pqrs_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1105R: Second generation, no TTEthernet, SGMII */
static const struct sja1105_table_ops sja1105r_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105pqrs_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105pqrs_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105pqrs_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105pqrs_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105pqrs_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1105S: Second generation, TTEthernet, SGMII */
static const struct sja1105_table_ops sja1105s_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = {
		.packing = sja1105_schedule_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = {
		.packing = sja1105_schedule_entry_points_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_COUNT,
	},
	[BLK_IDX_VL_LOOKUP] = {
		.packing = sja1105_vl_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VL_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_LOOKUP_COUNT,
	},
	[BLK_IDX_VL_POLICING] = {
		.packing = sja1105_vl_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_policing_entry),
		.packed_entry_size = SJA1105_SIZE_VL_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_POLICING_COUNT,
	},
	[BLK_IDX_VL_FORWARDING] = {
		.packing = sja1105_vl_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_COUNT,
	},
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1105pqrs_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1105_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1105_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1105_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1105pqrs_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1105_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_SCHEDULE_PARAMS] = {
		.packing = sja1105_schedule_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_PARAMS_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = {
		.packing = sja1105_schedule_entry_points_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_PARAMS_COUNT,
	},
	[BLK_IDX_VL_FORWARDING_PARAMS] = {
		.packing = sja1105_vl_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1105pqrs_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1105_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105pqrs_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1105pqrs_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1105_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1105_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1105_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
};

/* SJA1110A: Third generation */
static const struct sja1105_table_ops sja1110_table_ops[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = {
		.packing = sja1110_schedule_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry),
		.packed_entry_size = SJA1110_SIZE_SCHEDULE_ENTRY,
		.max_entry_count = SJA1110_MAX_SCHEDULE_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = {
		.packing = sja1110_schedule_entry_points_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_entry),
		.packed_entry_size = SJA1110_SIZE_SCHEDULE_ENTRY_POINTS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_COUNT,
	},
	[BLK_IDX_VL_LOOKUP] = {
		.packing = sja1110_vl_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_lookup_entry),
		.packed_entry_size = SJA1105_SIZE_VL_LOOKUP_ENTRY,
		.max_entry_count = SJA1110_MAX_VL_LOOKUP_COUNT,
	},
	[BLK_IDX_VL_POLICING] = {
		.packing = sja1110_vl_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_policing_entry),
		.packed_entry_size = SJA1105_SIZE_VL_POLICING_ENTRY,
		.max_entry_count = SJA1110_MAX_VL_POLICING_COUNT,
	},
	[BLK_IDX_VL_FORWARDING] = {
		.packing = sja1110_vl_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_ENTRY,
		.max_entry_count = SJA1110_MAX_VL_FORWARDING_COUNT,
	},
	[BLK_IDX_L2_LOOKUP] = {
		.packing = sja1110_l2_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_entry),
		.packed_entry_size = SJA1110_SIZE_L2_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_POLICING] = {
		.packing = sja1110_l2_policing_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_policing_entry),
		.packed_entry_size = SJA1105_SIZE_L2_POLICING_ENTRY,
		.max_entry_count = SJA1110_MAX_L2_POLICING_COUNT,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.packing = sja1110_vlan_lookup_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vlan_lookup_entry),
		.packed_entry_size = SJA1110_SIZE_VLAN_LOOKUP_ENTRY,
		.max_entry_count = SJA1105_MAX_VLAN_LOOKUP_COUNT,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.packing = sja1110_l2_forwarding_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_ENTRY,
		.max_entry_count = SJA1110_MAX_L2_FORWARDING_COUNT,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.packing = sja1110_mac_config_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_mac_config_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_MAC_CONFIG_ENTRY,
		.max_entry_count = SJA1110_MAX_MAC_CONFIG_COUNT,
	},
	[BLK_IDX_SCHEDULE_PARAMS] = {
		.packing = sja1110_schedule_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_PARAMS_COUNT,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = {
		.packing = sja1105_schedule_entry_points_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_schedule_entry_points_params_entry),
		.packed_entry_size = SJA1105_SIZE_SCHEDULE_ENTRY_POINTS_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_SCHEDULE_ENTRY_POINTS_PARAMS_COUNT,
	},
	[BLK_IDX_VL_FORWARDING_PARAMS] = {
		.packing = sja1110_vl_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_vl_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_VL_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_VL_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.packing = sja1110_l2_lookup_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_lookup_params_entry),
		.packed_entry_size = SJA1110_SIZE_L2_LOOKUP_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_LOOKUP_PARAMS_COUNT,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.packing = sja1110_l2_forwarding_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_l2_forwarding_params_entry),
		.packed_entry_size = SJA1105_SIZE_L2_FORWARDING_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_L2_FORWARDING_PARAMS_COUNT,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.packing = sja1105pqrs_avb_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_avb_params_entry),
		.packed_entry_size = SJA1105PQRS_SIZE_AVB_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_AVB_PARAMS_COUNT,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.packing = sja1110_general_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_general_params_entry),
		.packed_entry_size = SJA1110_SIZE_GENERAL_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_GENERAL_PARAMS_COUNT,
	},
	[BLK_IDX_RETAGGING] = {
		.packing = sja1110_retagging_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_retagging_entry),
		.packed_entry_size = SJA1105_SIZE_RETAGGING_ENTRY,
		.max_entry_count = SJA1105_MAX_RETAGGING_COUNT,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.packing = sja1110_xmii_params_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1105_xmii_params_entry),
		.packed_entry_size = SJA1110_SIZE_XMII_PARAMS_ENTRY,
		.max_entry_count = SJA1105_MAX_XMII_PARAMS_COUNT,
	},
	[BLK_IDX_PCP_REMAPPING] = {
		.packing = sja1110_pcp_remapping_entry_packing,
		.unpacked_entry_size = sizeof(struct sja1110_pcp_remapping_entry),
		.packed_entry_size = SJA1110_SIZE_PCP_REMAPPING_ENTRY,
		.max_entry_count = SJA1110_MAX_PCP_REMAPPING_COUNT,
	},
};

void sja1105_static_config_free(struct sja1105_static_config *config)
{
	enum sja1105_blk_idx i;

	for (i = 0; i < BLK_IDX_MAX; i++) {
		if (config->tables[i].entry_count) {
			free(config->tables[i].entries);
			config->tables[i].entry_count = 0;
		}
	}
}

static int buffer_advance(size_t *buf_len, size_t amount, const char *reason)
{
	if ((*buf_len) < amount) {
		fprintf(stderr, "Unexpected end of buffer: %s\n", reason);
		return -EINVAL;
	}

	(*buf_len) -= amount;
	return 0;
}

int sja1105_static_config_unpack(void *buf, size_t buf_len, size_t *parsed_len,
				 struct sja1105_static_config *config)
{
	const struct sja1105_table_ops *static_ops;
	struct sja1105_table_header hdr;
	enum sja1105_blk_idx blk_idx;
	struct sja1105_table *table;
	u64 computed_crc, read_crc;
	int expected_entry_count;
	enum sja1105_blk_idx i;
	u8 *table_end;
	u8 *p = buf;
	int bytes;
	int err;

	memset(config, 0, sizeof(*config));

	/* Consume device id */
	err = buffer_advance(&buf_len, 4, "device ID");
	if (err)
		return err;

	/* Retrieve device_id from first 4 bytes of packed buffer */
	sja1105_packing(p, &config->device_id, 31, 0, 4, UNPACK);

	switch (config->device_id) {
	case SJA1105E_DEVICE_ID:
		static_ops = sja1105e_table_ops;
		break;
	case SJA1105T_DEVICE_ID:
		static_ops = sja1105t_table_ops;
		break;
	case SJA1105PR_DEVICE_ID:
		static_ops = sja1105p_table_ops;
		break;
	case SJA1105QS_DEVICE_ID:
		static_ops = sja1105q_table_ops;
		break;
	case SJA1110_DEVICE_ID:
		static_ops = sja1110_table_ops;
		break;
	default:
		fprintf(stderr, "Device ID present in the static config is unknown: 0x%" PRIx64,
			config->device_id);
		return -EINVAL;
	}

	/* Transfer static_ops array from priv into per-table ops
	 * for handier access
	 */
	for (i = 0; i < BLK_IDX_MAX; i++)
		config->tables[i].ops = &static_ops[i];

	/* Advance buffer past device ID */
	p += SJA1105_SIZE_DEVICE_ID;

	while (1) {
		err = buffer_advance(&buf_len, SJA1105_SIZE_TABLE_HEADER,
				     "table header");
		if (err)
			return err;

		/* Discard const pointer due to common implementation
		 * of PACK and UNPACK.
		 */
		hdr = (struct sja1105_table_header) {0};
		sja1105_table_header_packing((void *)p, &hdr, UNPACK);

		/* This should match on last table header */
		if (hdr.len == 0)
			break;

		computed_crc = sja1105_crc32(p, SJA1105_SIZE_TABLE_HEADER - 4);
		computed_crc &= 0xFFFFFFFF;
		read_crc = hdr.crc & 0xFFFFFFFF;
		if (read_crc != computed_crc) {
			fprintf(stderr, "Invalid CRC: read 0x%" PRIx64
				", expected 0x%" PRIx64 "\n",
				read_crc, computed_crc);
			return -EINVAL;
		}

		p += SJA1105_SIZE_TABLE_HEADER;

		err = buffer_advance(&buf_len, hdr.len * 4, "table");
		if (err)
			return err;

		table_end = p + hdr.len * 4;
		computed_crc = sja1105_crc32(p, hdr.len * 4);

		blk_idx = blk_idx_from_blk_id(hdr.block_id);
		if (blk_idx == BLK_IDX_INVAL) {
			fprintf(stderr, "Invalid block ID 0x%" PRIx64 "\n",
				hdr.block_id);
			return -EINVAL;
		}

		table = &config->tables[blk_idx];
		/* Detected duplicate table headers with the same block id */
		if (table->entry_count) {
			fprintf(stderr, "Duplicate block ID 0x%" PRIx64 "\n",
				hdr.block_id);
			return -EINVAL;
		}

		expected_entry_count = hdr.len * 4;
		expected_entry_count /= table->ops->packed_entry_size;
		table->entries = calloc(expected_entry_count,
					table->ops->unpacked_entry_size);
		if (!table->entries)
			return -ENOMEM;

		while (p < table_end) {
			bytes = sja1105_table_add_entry(table, p);
			if (bytes < 0) {
				fprintf(stderr, "One of the table headers contains an invalid block id\n");
				return -EINVAL;
			}
			p += bytes;
		}
		if (p != table_end) {
			/* Incorrect table length for this block id:
			 * table data has (table_end - p) extra bytes.
			 */
			fprintf(stderr, "The data length specified in one of the table headers is longer than the actual size of the entries that were parsed");
			return -EINVAL;
		}

		err = buffer_advance(&buf_len, 4, "CRC");
		if (err)
			return err;

		sja1105_packing(p, &read_crc, 31, 0, 4, UNPACK);
		p += 4;
		if (computed_crc != read_crc) {
			fprintf(stderr, "One of the tables has an incorrect CRC over the data area");
			return -EINVAL;
		}
	}

	*parsed_len = p - (u8 *)buf;

	return 0;
}
