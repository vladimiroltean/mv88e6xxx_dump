// SPDX-License-Identifier: GPL-v2.0
/* Copyright 2020 Andrew Lunn <andrew@lunn.ch>
 * Copyright 2020 Vladimir Oltean <vladimir.oltean@nxp.com>
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include "linux/devlink.h"
#include <linux/genetlink.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sja1105_static_config.h"
#include "mnlg.h"
#include "utils.h"

/* All single snapshots used by this program have this ID. */
#define SNAPSHOT_ID			42
#define MAX_SNAPSHOT_DATA		1000 * 1024
#define MAX_PORTS			11

#define FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/

enum sja1105_asic {
	SJA1105E,
	SJA1105T,
	SJA1105P,
	SJA1105Q,
	SJA1105R,
	SJA1105S,
	SJA1110A,
	SJA1110B,
	SJA1110C,
	SJA1110D,
	__SJA1105_NUM_ASIC,
};

struct sja1105_asic_info {
	const char *name;
};

static const struct sja1105_asic_info sja1105_info[] = {
	[SJA1105E] = {
		.name = "SJA1105E",
	},
	[SJA1105T] = {
		.name = "SJA1105T",
	},
	[SJA1105P] = {
		.name = "SJA1105P",
	},
	[SJA1105Q] = {
		.name = "SJA1105Q",
	},
	[SJA1105R] = {
		.name = "SJA1105R",
	},
	[SJA1105S] = {
		.name = "SJA1105S",
	},
	[SJA1110A] = {
		.name = "SJA1110A",
	},
	[SJA1110B] = {
		.name = "SJA1110B",
	},
	[SJA1110C] = {
		.name = "SJA1110C",
	},
	[SJA1110D] = {
		.name = "SJA1110D",
	},
};

struct sja1105_snapshot {
	LIST_ENTRY(sja1105_snapshot) list;
	uint32_t port;
	uint32_t id;
	const char *region_name;
};

struct sja1105_ctx {
	struct mnlg_socket *nlg;
	const struct sja1105_asic_info *info;
	const char *bus_name;
	const char *dev_name;
	unsigned int chip;
	int ports;
	bool repeat;
	LIST_HEAD(snapshots_head, sja1105_snapshot) snapshots;
	uint8_t snapshot_data[MAX_SNAPSHOT_DATA];
	size_t data_len;
};

void usage(const char *progname)
{
	printf("%s [OPTIONs]\n", progname);
	printf("  --debug/-d\tExtra debug output\n");
	printf("  --list/-l\tList the devices\n");
	printf("  --device/-d\tDump this device\n");
	printf("  --static-config\t\tDump the static config\n");

	exit(EXIT_FAILURE);
}

static int _mnlg_socket_recv_run(struct mnlg_socket *nlg,
				 mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_recv_run(nlg, data_cb, data);
	if (err < 0) {
		printf("devlink answers: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

static int _mnlg_socket_send(struct mnlg_socket *nlg,
			     const struct nlmsghdr *nlh)
{
	int err;

	err = mnlg_socket_send(nlg, nlh);
	if (err < 0) {
		printf("Failed to call mnlg_socket_send\n");
		return -errno;
	}
	return 0;
}

static int _mnlg_socket_sndrcv(struct mnlg_socket *nlg,
			       const struct nlmsghdr *nlh,
			       mnl_cb_t data_cb, void *data)
{
	int err;

	err = _mnlg_socket_send(nlg, nlh);
	if (err)
		return err;

	return _mnlg_socket_recv_run(nlg, data_cb, data);
}

static const enum mnl_attr_data_type devlink_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_BUS_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_DEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_PORT_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PORT_TYPE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_PORT_DESIRED_TYPE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_PORT_NETDEV_IFINDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PORT_NETDEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_PORT_IBDEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_SB_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_SIZE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_INGRESS_TC_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_EGRESS_TC_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_POOL_INDEX] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_POOL_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_SB_POOL_SIZE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_SB_THRESHOLD] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_TC_INDEX] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_OCC_CUR] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_OCC_MAX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_ESWITCH_MODE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_ESWITCH_INLINE_MODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_ESWITCH_ENCAP_MODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_TABLES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_TABLE_SIZE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_TABLE_MATCHES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED] =  MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_ENTRIES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_INDEX] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_MATCH] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_MATCH_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_MATCH_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_ACTION] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ACTION_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ACTION_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_VALUE_MAPPING] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_HEADERS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_HEADER_FIELDS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_HEADER_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_FIELD_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PARAM] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_PARAM_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_PARAM_VALUES_LIST] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_VALUE_CMODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_REGION_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_REGION_SIZE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_REGION_SNAPSHOTS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_SNAPSHOT] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_SNAPSHOT_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_REGION_CHUNKS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_CHUNK] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_CHUNK_DATA] = MNL_TYPE_BINARY,
	[DEVLINK_ATTR_REGION_CHUNK_ADDR] = MNL_TYPE_U64,
	[DEVLINK_ATTR_REGION_CHUNK_LEN] = MNL_TYPE_U64,
	[DEVLINK_ATTR_INFO_DRIVER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_SERIAL_NUMBER] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_VERSION_FIXED] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_RUNNING] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_STORED] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_VERSION_VALUE] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_HEALTH_REPORTER] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_HEALTH_REPORTER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_HEALTH_REPORTER_STATE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD] = MNL_TYPE_U64,
	[DEVLINK_ATTR_FLASH_UPDATE_COMPONENT] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL] = MNL_TYPE_U64,
	[DEVLINK_ATTR_STATS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_TRAP_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_TRAP_ACTION] = MNL_TYPE_U8,
	[DEVLINK_ATTR_TRAP_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_TRAP_GENERIC] = MNL_TYPE_FLAG,
	[DEVLINK_ATTR_TRAP_METADATA] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_TRAP_GROUP_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_RELOAD_FAILED] = MNL_TYPE_U8,
};

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, DEVLINK_ATTR_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, devlink_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	printf("%s/%s\n",
	       mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]),
	       mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]));

	return MNL_CB_OK;
}

static void list(struct sja1105_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_GET, flags);
	_mnlg_socket_sndrcv(ctx->nlg, nlh, list_cb, ctx);
}

static int first_device_cb(const struct nlmsghdr *nlh, void *data)
{
	struct sja1105_ctx *ctx = data;
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	if (!ctx->bus_name) {
		ctx->bus_name = strdup(mnl_attr_get_str(
					       tb[DEVLINK_ATTR_BUS_NAME]));
		ctx->dev_name = strdup(mnl_attr_get_str(
					       tb[DEVLINK_ATTR_DEV_NAME]));
	}

	/* TODO Check this actually is a sja1105 device */

	return MNL_CB_OK;
}

static void first_device(struct sja1105_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_GET, flags);
	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, first_device_cb, ctx);
	if (err) {
		printf("Error determining first device");
		exit(EXIT_FAILURE);
	}

	if (!ctx->bus_name || !ctx->dev_name) {
		printf("No devlink devices found\n");
		exit(EXIT_FAILURE);
	}
}

static void queue_snapshot_port_id(struct sja1105_ctx *ctx,
				   uint32_t port, const char *region_name,
				   uint32_t id)
{
	struct sja1105_snapshot *snapshot;

	snapshot = calloc(1, sizeof(*snapshot));
	if (!snapshot) {
		fprintf(stderr, "Low memory");
		exit(1);
	}

	snapshot->port = port;
	snapshot->id = id;
	snapshot->region_name = region_name;
	LIST_INSERT_HEAD(&ctx->snapshots, snapshot, list);
}

static void delete_snapshot(struct sja1105_ctx *ctx,
			    struct sja1105_snapshot *snapshot)
{
	struct nlmsghdr *nlh;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_DEL,
			       NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	if (snapshot->port != ~0)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, snapshot->port);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, snapshot->region_name);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, snapshot->id);

	_mnlg_socket_sndrcv(ctx->nlg, nlh, NULL, NULL);

	ctx->repeat = true;
}

static void queue_snapshot(struct sja1105_ctx *ctx, struct nlattr **tb)
{
	struct nlattr *tb_snapshot[DEVLINK_ATTR_MAX + 1] = {};
	struct nlattr *nla_sanpshot;
	const char * region_name;
	uint32_t snapshot_id;
	uint32_t port = ~0;
	int err;

	region_name = mnl_attr_get_str(tb[DEVLINK_ATTR_REGION_NAME]);

	if (tb[DEVLINK_ATTR_PORT_INDEX])
		port = mnl_attr_get_u32(tb[DEVLINK_ATTR_PORT_INDEX]);

	mnl_attr_for_each_nested(nla_sanpshot,
				 tb[DEVLINK_ATTR_REGION_SNAPSHOTS]) {
		err = mnl_attr_parse_nested(nla_sanpshot, attr_cb, tb_snapshot);
		if (err != MNL_CB_OK)
			return;

		if (!tb_snapshot[DEVLINK_ATTR_REGION_SNAPSHOT_ID])
			return;

		snapshot_id = mnl_attr_get_u32(
			tb_snapshot[DEVLINK_ATTR_REGION_SNAPSHOT_ID]);

		queue_snapshot_port_id(ctx, port, region_name, snapshot_id);
	}
}

static int delete_snapshots_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct sja1105_ctx *ctx = data;
	int port;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_REGION_NAME] || !tb[DEVLINK_ATTR_REGION_SIZE])
		return MNL_CB_ERROR;

	if (tb[DEVLINK_ATTR_REGION_SNAPSHOTS])
		queue_snapshot(ctx, tb);

	return MNL_CB_OK;
}

static void delete_snapshots(struct sja1105_ctx *ctx)
{
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	struct sja1105_snapshot *snapshot, *tmp;
	struct nlmsghdr *nlh;

	/* Sending a new message while decoding an older message
	 * results in problems. So keep repeating until all regions
	 * snapshots are gone. */
	do {
		ctx->repeat = false;
		nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_GET, flags);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);

		_mnlg_socket_sndrcv(ctx->nlg, nlh, delete_snapshots_cb, ctx);
	} while (ctx->repeat);

	LIST_FOREACH_SAFE(snapshot, &ctx->snapshots, list, tmp) {
		delete_snapshot(ctx, snapshot);
		LIST_REMOVE(snapshot, list);
		free(snapshot);
	}
}

static int new_snapshot_port_id(struct sja1105_ctx *ctx,
				uint32_t port, const char *region_name,
				uint32_t id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_NEW,
			       NLM_F_REQUEST | NLM_F_ACK);

	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, region_name);
	if (port != ~0)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, port);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, id);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, NULL, NULL);
	if (err)
		printf("Unable to snapshot %s\n", region_name);

	return err;
}

static int new_snapshot_id(struct sja1105_ctx *ctx, const char *region_name,
			   uint32_t id)
{
	return new_snapshot_port_id(ctx, ~0, region_name, id);
}

static int new_snapshot(struct sja1105_ctx *ctx, const char *region_name)
{
	return new_snapshot_id(ctx, region_name, SNAPSHOT_ID);
}

void dump_snapshot_add_data(struct sja1105_ctx *ctx,
			    const uint8_t *data, size_t len,
			    uint64_t addr)
{
	if (addr > MAX_SNAPSHOT_DATA) {
		printf("Data ignored, start address outside buffer\n");
		return;
	}

	if (addr + len > MAX_SNAPSHOT_DATA) {
		printf("Data truncated\n");
		len = MAX_SNAPSHOT_DATA - addr;
	}
	memcpy(ctx->snapshot_data + addr, data, len);
	ctx->data_len = addr + len;
}

static int dump_snapshot_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *nla_entry, *nla_chunk_data, *nla_chunk_addr;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb_field[DEVLINK_ATTR_MAX + 1] = {};
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct sja1105_ctx *ctx = data;
	int err;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_REGION_CHUNKS])
		return MNL_CB_ERROR;

	mnl_attr_for_each_nested(nla_entry, tb[DEVLINK_ATTR_REGION_CHUNKS]) {
		err = mnl_attr_parse_nested(nla_entry, attr_cb, tb_field);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		nla_chunk_data = tb_field[DEVLINK_ATTR_REGION_CHUNK_DATA];
		if (!nla_chunk_data)
			continue;

		nla_chunk_addr = tb_field[DEVLINK_ATTR_REGION_CHUNK_ADDR];
		if (!nla_chunk_addr)
			continue;

		dump_snapshot_add_data(ctx,
				       mnl_attr_get_payload(nla_chunk_data),
				       mnl_attr_get_payload_len(nla_chunk_data),
				       mnl_attr_get_u64(nla_chunk_addr));
	}
	return MNL_CB_OK;
}

static int dump_snapshot_port_id(struct sja1105_ctx *ctx,
				 uint32_t port, const char *region_name,
				 uint32_t id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_READ,
			       NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);

	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	if (port != ~0)
		mnl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, port);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, region_name);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, id);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, dump_snapshot_cb, ctx);
	if (err)
		printf("Unable to dump snapshot %s\n", region_name);

	return err;
}

static int dump_snapshot_id(struct sja1105_ctx *ctx,
				 const char *region_name, uint32_t id)
{
	return dump_snapshot_port_id(ctx, ~0, region_name, id);
}

static int dump_snapshot(struct sja1105_ctx *ctx, const char *region_name)
{
	return dump_snapshot_id(ctx, region_name, SNAPSHOT_ID);
}

/**
 * u64_to_ether_addr - Convert a u64 to an Ethernet address.
 * @u: u64 to convert to an Ethernet MAC address
 * @addr: Pointer to a six-byte array to contain the Ethernet address
 */
static inline void u64_to_ether_addr(u64 u, u8 *addr)
{
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--) {
		addr[i] = u & 0xff;
		u = u >> 8;
	}
}

static void print_mac(char *buf, u8 mac[ETH_ALEN])
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_port_mask(char *buf, u64 port_mask)
{
	int bit;

	if (!port_mask) {
		sprintf(buf, "no ports");
		return;
	}

	sprintf(buf, "ports: ");
	buf += strlen("ports: ");

	for (bit = 0; bit < 63; bit++)
		if (port_mask & BIT_ULL(bit))
			buf += sprintf(buf, "%d, ", bit);
}

static void sja1105_schedule_entry_dump(void *entry)
{
	struct sja1105_schedule_entry *e = entry;
	char buf[BUFSIZ];

	printf("WINSTINDEX:	%" PRIu64 "\n",		e->winstindex);
	printf("WINEND:		%" PRIu64 "\n",		e->winend);
	printf("WINST:		%" PRIu64 "\n",		e->winst);
	print_port_mask(buf, e->destports);
	printf("DESTPORTS:	%s\n",			buf);
	printf("SETVALID:	%" PRIu64 "\n",		e->setvalid);
	printf("TXEN:		%" PRIu64 "\n",		e->txen);
	printf("RESMEDIA:	0x%" PRIx64 "\n",	e->resmedia);
	printf("VLINDEX:	%" PRIu64 "\n",		e->vlindex);
	printf("DELTA:		%" PRIu64 "\n",		e->delta);
}

static void sja1105_schedule_entry_points_entry_dump(void *entry)
{
	struct sja1105_schedule_entry_points_entry *e = entry;

	printf("SUBSCHINDX:	%" PRIu64 "\n",		e->subschindx);
	printf("DELTA:		%" PRIu64 "\n",		e->delta);
	printf("ADDRESS:	%" PRIu64 "\n",		e->address);
}

static void sja1105_vl_lookup_entry_dump(void *entry)
{
	struct sja1105_vl_lookup_entry *e = entry;
	char buf[BUFSIZ];
	u8 mac[ETH_ALEN];

	if (e->format == SJA1105_VL_FORMAT_PSFP) {
		printf("Format: PSFP (0)\n");
		print_port_mask(buf, e->destports);
		printf("DESTPORTS:	%s\n",		buf);
		printf("ISCRITICAL:	%" PRIu64 "\n",	e->iscritical);
		u64_to_ether_addr(e->macaddr, mac);
		print_mac(buf, mac);
		printf("MACADDR:	%s\n",		buf);
		printf("VLANID:		%" PRIu64 "\n",	e->vlanid);
		printf("VLANPRIOR:	%" PRIu64 "\n",	e->vlanprior);
		printf("PORT:		%" PRIu64 "\n",	e->port);
	} else {
		printf("Format: ARINC664 (1)\n");
		print_port_mask(buf, e->egrmirr);
		printf("EGRMIRR:	%s\n",		buf);
		print_port_mask(buf, e->ingrmirr);
		printf("INGRMIRR:	%s\n",		buf);
		printf("VLID:		%" PRIu64 "\n",	e->vlid);
		printf("PORT:		%" PRIu64 "\n",	e->port);
	}
}

static void sja1105_vl_policing_entry_dump(void *entry)
{
	struct sja1105_vl_policing_entry *e = entry;

	if (e->type == 1) {
		printf("TTRC: Time-triggered (1)\n");
		printf("MAXLEN:		%" PRIu64 "\n",	e->maxlen);
		printf("SHARINDX:	%" PRIu64 "\n",	e->sharindx);
	} else {
		printf("TTRC: Rate-constrained (0)\n");
		printf("MAXLEN:		%" PRIu64 "\n",	e->maxlen);
		printf("SHARINDX:	%" PRIu64 "\n",	e->sharindx);
		printf("BAG:		%" PRIu64 "\n",	e->bag);
		printf("JITTER:		%" PRIu64 "\n",	e->jitter);
	}
}

static void sja1105_vl_forwarding_entry_dump(void *entry)
{
	struct sja1105_vl_forwarding_entry *e = entry;
	char buf[BUFSIZ];

	if (e->type == 1)
		printf("Type: Time-triggered (1)\n");
	else
		printf("Type: Rate-constrained (0)\n");

	printf("PRIORITY:	%" PRIu64 "\n",		e->priority);
	printf("PARTITION:	%" PRIu64 "\n",		e->partition);
	print_port_mask(buf, e->destports);
	printf("DESTPORTS:	%s\n",			buf);
}

static void sja1105_l2_lookup_entry_dump(void *entry)
{
	struct sja1105_l2_lookup_entry *e = entry;
	char buf[BUFSIZ];
	u8 mac[ETH_ALEN];

	printf("INDEX:		%" PRIu64 "\n",		e->index);
	printf("VLANID:		%" PRIu64 "\n",		e->vlanid);
	printf("MASK_VLANID:	0x%" PRIx64 "\n",	e->mask_vlanid);
	u64_to_ether_addr(e->macaddr, mac);
	print_mac(buf, mac);
	printf("MACADDR:	%s\n",			buf);
	u64_to_ether_addr(e->mask_macaddr, mac);
	print_mac(buf, mac);
	printf("MASK_MACADDR:	%s\n",			buf);
	print_port_mask(buf, e->destports);
	printf("IOTAG:		%" PRIu64 "\n",		e->iotag);
	printf("MASK_IOTAG:	%" PRIu64 "\n",		e->mask_iotag);
	printf("DESTPORTS:	%s\n",			buf);
	printf("ENFPORT:	%" PRIu64 "\n",		e->enfport);
	printf("TSREG:		%" PRIu64 "\n",		e->tsreg);
	printf("MIRRVLAN:	%" PRIu64 "\n",		e->mirrvlan);
	printf("TRAP:		%" PRIu64 "\n",		e->trap);
	printf("TAKETS:		%" PRIu64 "\n",		e->takets);
	printf("MIRR:		%" PRIu64 "\n",		e->mirr);
	printf("RETAG:		%" PRIu64 "\n",		e->retag);
}

static void sja1105_l2_policing_entry_dump(void *entry)
{
	struct sja1105_l2_policing_entry *e = entry;

	printf("SHARINDX:	%" PRIu64 "\n",		e->sharindx);
	printf("SMAX:		%" PRIu64 "\n",		e->smax);
	printf("RATE:		%" PRIu64 "\n",		e->rate);
	printf("MAXLEN:		%" PRIu64 "\n",		e->maxlen);
	printf("PARTITION:	%" PRIu64 "\n",		e->partition);
}

static void sja1105_vlan_lookup_entry_dump(void *entry)
{
	struct sja1105_vlan_lookup_entry *e = entry;
	char buf[BUFSIZ];

	print_port_mask(buf, e->ving_mirr);
	printf("VING_MIRR:	%s\n",			buf);
	print_port_mask(buf, e->vegr_mirr);
	printf("VEGR_MIRR:	%s\n",			buf);
	print_port_mask(buf, e->vmemb_port);
	printf("VMEMB_PORT:	%s\n",			buf);
	print_port_mask(buf, e->vlan_bc);
	printf("VLAN_BC:	%s\n",			buf);
	print_port_mask(buf, e->tag_port);
	printf("TAG_PORT:	%s\n",			buf);
	printf("VLANID:		%" PRIu64 "\n",		e->vlanid);
	printf("TYPE_ENTRY:	%" PRIu64 "\n",		e->type_entry);
}

static void sja1105_l2_forwarding_entry_dump(void *entry)
{
	struct sja1105_l2_forwarding_entry *e = entry;
	char buf[BUFSIZ];
	int i;

	print_port_mask(buf, e->bc_domain);
	printf("BC_DOMAIN:	%s\n",			buf);
	print_port_mask(buf, e->reach_port);
	printf("REACH_PORT:	%s\n",			buf);
	print_port_mask(buf, e->fl_domain);
	printf("FL_DOMAIN:	%s\n",			buf);

	for (i = 0; i < SJA1105_MAX_NUM_PORTS; i++)
		printf("VLAN_PMAP[%d]:	%" PRIu64 "\n", i, e->vlan_pmap[i]);
}

static void sja1105_mac_config_entry_dump(void *entry)
{
	struct sja1105_mac_config_entry *e = entry;
	char buf[BUFSIZ];
	int i;

	for (i = 0; i < 8; i++) {
		printf("BASE[%d]:	%" PRIu64 "\n", i, e->base[i]);
		printf("TOP[%d]:		%" PRIu64 "\n", i, e->top[i]);
		printf("ENABLED[%d]:	%" PRIu64 "\n", i, e->enabled[i]);
	}

	printf("IFG:		%" PRIu64 "\n",		e->ifg);
	printf("SPEED:		%" PRIu64 "\n",		e->speed);
	printf("TP_DELIN:	%" PRIu64 "\n",		e->tp_delin);
	printf("TP_DELOUT:	%" PRIu64 "\n",		e->tp_delout);
	printf("MAXAGE:		%" PRIu64 "\n",		e->maxage);
	printf("VLANPRIO:	%" PRIu64 "\n",		e->vlanprio);
	printf("VLANID:		%" PRIu64 "\n",		e->vlanid);
	print_port_mask(buf, e->ing_mirr);
	printf("ING_MIRR:	%s\n",			buf);
	print_port_mask(buf, e->egr_mirr);
	printf("EGR_MIRR:	%s\n",			buf);
	printf("DRPNONA644:	%" PRIu64 "\n",		e->drpnona664);
	printf("DRPDTAG:	%" PRIu64 "\n",		e->drpdtag);
	printf("DRPUNTAG:	%" PRIu64 "\n",		e->drpuntag);
	printf("RETAG:		%" PRIu64 "\n",		e->retag);
	printf("DYN_LEARN:	%" PRIu64 "\n",		e->dyn_learn);
	printf("EGRESS:		%" PRIu64 "\n",		e->egress);
	printf("INGRESS:	%" PRIu64 "\n",		e->ingress);
}

static void sja1105_schedule_params_entry_dump(void *entry)
{
	struct sja1105_schedule_params_entry *e = entry;
	int i;

	for (i = 0; i < 8; i++)
		printf("SUBSCHEIND[%d]:	%" PRIu64 "\n", i, e->subscheind[i]);
}

static void sja1105_schedule_entry_points_params_entry_dump(void *entry)
{
	struct sja1105_schedule_entry_points_params_entry *e = entry;

	printf("CLKSRC:		%" PRIu64 "\n",		e->clksrc);
	printf("ACTSUBSCH:	%" PRIu64 "\n",		e->actsubsch);
}

static void sja1105_vl_forwarding_params_entry_dump(void *entry)
{
	struct sja1105_vl_forwarding_params_entry *e;

}

static void sja1105_l2_lookup_params_entry_dump(void *entry)
{
	struct sja1105_l2_lookup_params_entry *e = entry;
	int i;

	for (i = 0; i < SJA1105_MAX_NUM_PORTS; i++)
		printf("MAXADDRP[%d]:	%" PRIu64 "\n", i, e->maxaddrp[i]);

	printf("START_DYNSPC:	%" PRIu64 "\n",		e->start_dynspc);
	printf("DRPNOLEARN:	%" PRIu64 "\n",		e->drpnolearn);
	printf("USE_STATIC:	%" PRIu64 "\n",		e->use_static);
	printf("OWR_DYN:	%" PRIu64 "\n",		e->owr_dyn);
	printf("LEARN_ONCE:	%" PRIu64 "\n",		e->learn_once);
	printf("MAXAGE:		%" PRIu64 "\n",		e->maxage);
	printf("DYN_TBSZ:	%" PRIu64 "\n",		e->dyn_tbsz);
	printf("POLY:		0x%" PRIx64 "\n",	e->poly);
	printf("SHARED_LEARN:	%" PRIu64 "\n",		e->shared_learn);
	printf("NO_ENF_HOSTPRT:	%" PRIu64 "\n",		e->no_enf_hostprt);
	printf("NO_MGMT_LEARN:	%" PRIu64 "\n",		e->no_mgmt_learn);
}

static void sja1105_l2_forwarding_params_entry_dump(void *entry)
{
	struct sja1105_l2_forwarding_params_entry *e = entry;
	int i;

	printf("MAX_DYNP:	%" PRIu64 "\n",		e->max_dynp);

	for (i = 0; i < 8; i++)
		printf("PART_SPC[%d]:	%" PRIu64 "\n", i, e->part_spc[i]);
}

static void sja1105_avb_params_entry_dump(void *entry)
{
	struct sja1105_avb_params_entry *e = entry;
	char buf[BUFSIZ];
	u8 mac[ETH_ALEN];

	printf("CAS_MASTER:	%" PRIu64 "\n",		e->cas_master);
	u64_to_ether_addr(e->destmeta, mac);
	print_mac(buf, mac);
	printf("DESTMETA:	%s\n",			buf);
	u64_to_ether_addr(e->srcmeta, mac);
	print_mac(buf, mac);
	printf("SRCMETA:	%s\n",			buf);
}

static void sja1105_general_params_entry_dump(void *entry)
{
	struct sja1105_general_params_entry *e = entry;
	char buf[BUFSIZ];
	u8 mac[ETH_ALEN];

	printf("VLLUPFORMAT:	%" PRIu64 "\n",		e->vllupformat);
	printf("MIRR_PTACU:	%" PRIu64 "\n",		e->mirr_ptacu);
	printf("SWITCHID:	%" PRIu64 "\n",		e->switchid);
	printf("HOSTPRIO:	%" PRIu64 "\n",		e->hostprio);
	u64_to_ether_addr(e->mac_fltres1, mac);
	print_mac(buf, mac);
	printf("MAC_FLTRES1:	%s\n",			buf);
	u64_to_ether_addr(e->mac_fltres0, mac);
	print_mac(buf, mac);
	printf("MAC_FLTRES0:	%s\n",			buf);
	u64_to_ether_addr(e->mac_flt1, mac);
	print_mac(buf, mac);
	printf("MAC_FLT1:	%s\n",			buf);
	u64_to_ether_addr(e->mac_flt0, mac);
	print_mac(buf, mac);
	printf("MAC_FLT0:	%s\n",			buf);
	printf("INCL_SRCPT1:	%" PRIu64 "\n",		e->incl_srcpt1);
	printf("INCL_SRCPT0:	%" PRIu64 "\n",		e->incl_srcpt0);
	printf("SEND_META1:	%" PRIu64 "\n",		e->send_meta1);
	printf("SEND_META0:	%" PRIu64 "\n",		e->send_meta0);
	printf("CASC_PORT:	%" PRIu64 "\n",		e->casc_port);
	printf("HOST_PORT:	%" PRIu64 "\n",		e->host_port);
	printf("MIRR_PORT:	%" PRIu64 "\n",		e->mirr_port);
	printf("VLMARKER:	0x%" PRIx64 "\n",	e->vlmarker);
	printf("VLMASK:		0x%" PRIx64 "\n",	e->vlmask);
	printf("TPID:		0x%" PRIx64 "\n",	e->tpid);
	printf("TPID2:		0x%" PRIx64 "\n",	e->tpid2);
	printf("IGNORE2STF:	%" PRIu64 "\n",		e->ignore2stf);
	printf("QUEUE_TS:	%" PRIu64 "\n",		e->queue_ts);
	printf("EGRMIRRVID:	%" PRIu64 "\n",		e->egrmirrvid);
	printf("EGRMIRRPCP:	%" PRIu64 "\n",		e->egrmirrpcp);
	printf("EGRMIRRDEI:	%" PRIu64 "\n",		e->egrmirrdei);
	printf("REPLAY_PORT:	%" PRIu64 "\n",		e->replay_port);
	printf("TDMACONFIGIDX:	%" PRIu64 "\n",		e->tdmaconfigidx);
	printf("HEADER_TYPE:	0x%" PRIx64 "\n",	e->header_type);
	printf("TS_THRESHOLD:	%" PRIu64 "\n",		e->ts_threshold);
	printf("TS_TIMEOUT:	%" PRIu64 "\n",		e->ts_timeout);
	printf("TTE_EN:		%" PRIu64 "\n",		e->tte_en);
}

static void sja1105_retagging_entry_dump(void *entry)
{
	struct sja1105_retagging_entry *e = entry;
	char buf[BUFSIZ];

	print_port_mask(buf, e->egr_port);
	printf("EGR_PORT:	%s\n",			buf);
	print_port_mask(buf, e->ing_port);
	printf("ING_PORT:	%s\n",			buf);
	printf("VLAN_ING:	%" PRIu64 "\n",		e->vlan_ing);
	printf("VLAN_EGR:	%" PRIu64 "\n",		e->vlan_egr);
	printf("DO_NOT_LEARN:	%" PRIu64 "\n",		e->do_not_learn);
	printf("USE_DEST_PORTS:	%" PRIu64 "\n",		e->use_dest_ports);
	print_port_mask(buf, e->destports);
	printf("DESTPORTS:	%s\n",			buf);
}

static void sja1105_xmii_params_entry_dump(void *entry)
{
	struct sja1105_xmii_params_entry *e = entry;
	int i;

	for (i = 0; i < SJA1105_MAX_NUM_PORTS; i++) {
		printf("PHY_MAC[%d]:	%" PRIu64 "\n", i, e->phy_mac[i]);
		printf("XMII_MODE[%d]:	%" PRIu64 "\n", i, e->xmii_mode[i]);
		printf("SPECIAL[%d]:	%" PRIu64 "\n", i, e->special[i]);
	}
}

static void sja1110_pcp_remapping_entry_dump(void *entry)
{
	struct sja1110_pcp_remapping_entry *e = entry;
	int i;

	for (i = 0; i < SJA1105_NUM_TC; i++)
		printf("EGRPCP[%d]:	%" PRIu64 "\n", i, e->egrpcp[i]);
}

struct sja1105_table_dump_ops {
	const char *name;
	void (*dump)(void *entry);
};

static const struct sja1105_table_dump_ops sja1105_dump_ops[BLK_IDX_MAX] = {
	[BLK_IDX_SCHEDULE] = {
		.name = "Schedule",
		.dump = sja1105_schedule_entry_dump,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS] = {
		.name = "Schedule Entry Points",
		.dump = sja1105_schedule_entry_points_entry_dump,
	},
	[BLK_IDX_VL_LOOKUP] = {
		.name = "Virtual Link Lookup",
		.dump = sja1105_vl_lookup_entry_dump,
	},
	[BLK_IDX_VL_POLICING] = {
		.name = "Virtual Link Policing",
		.dump = sja1105_vl_policing_entry_dump,
	},
	[BLK_IDX_VL_FORWARDING] = {
		.name = "Virtual Link Forwarding",
		.dump = sja1105_vl_forwarding_entry_dump,
	},
	[BLK_IDX_L2_LOOKUP] = {
		.name = "L2 Address Lookup",
		.dump = sja1105_l2_lookup_entry_dump,
	},
	[BLK_IDX_L2_POLICING] = {
		.name = "L2 Policing",
		.dump = sja1105_l2_policing_entry_dump,
	},
	[BLK_IDX_VLAN_LOOKUP] = {
		.name = "VLAN Lookup",
		.dump = sja1105_vlan_lookup_entry_dump,
	},
	[BLK_IDX_L2_FORWARDING] = {
		.name = "L2 Forwarding",
		.dump = sja1105_l2_forwarding_entry_dump,
	},
	[BLK_IDX_MAC_CONFIG] = {
		.name = "MAC Configuration",
		.dump = sja1105_mac_config_entry_dump,
	},
	[BLK_IDX_SCHEDULE_PARAMS] = {
		.name = "Schedule Parameters",
		.dump = sja1105_schedule_params_entry_dump,
	},
	[BLK_IDX_SCHEDULE_ENTRY_POINTS_PARAMS] = {
		.name = "Schedule Entry Points Parameters",
		.dump = sja1105_schedule_entry_points_params_entry_dump,
	},
	[BLK_IDX_VL_FORWARDING_PARAMS] = {
		.name = "Virtual Link Forwarding Parameters",
		.dump = sja1105_vl_forwarding_params_entry_dump,
	},
	[BLK_IDX_L2_LOOKUP_PARAMS] = {
		.name = "L2 Address Lookup Parameters",
		.dump = sja1105_l2_lookup_params_entry_dump,
	},
	[BLK_IDX_L2_FORWARDING_PARAMS] = {
		.name = "L2 Forwarding Parameters",
		.dump = sja1105_l2_forwarding_params_entry_dump,
	},
	[BLK_IDX_AVB_PARAMS] = {
		.name = "AVB Parameters",
		.dump = sja1105_avb_params_entry_dump,
	},
	[BLK_IDX_GENERAL_PARAMS] = {
		.name = "General Parameters",
		.dump = sja1105_general_params_entry_dump,
	},
	[BLK_IDX_RETAGGING] = {
		.name = "Retagging",
		.dump = sja1105_retagging_entry_dump,
	},
	[BLK_IDX_XMII_PARAMS] = {
		.name = "XMII Mode",
		.dump = sja1105_xmii_params_entry_dump,
	},
	[BLK_IDX_PCP_REMAPPING] = {
		.name = "PCP Remapping",
		.dump = sja1110_pcp_remapping_entry_dump,
	},
};

static int sja1105_dump_static_config(struct sja1105_ctx *ctx)
{
	struct sja1105_static_config config;
	enum sja1105_blk_idx blk_idx;
	size_t parsed_len;
	int err;

	err = sja1105_static_config_unpack(ctx->snapshot_data, ctx->data_len,
					   &parsed_len, &config);
	if (err)
		return err;

	for (blk_idx = 0; blk_idx < BLK_IDX_MAX; blk_idx++) {
		struct sja1105_table *table = &config.tables[blk_idx];
		void *entry;
		int i;

		if (!table->entry_count)
			continue;

		printf("%s Table:\n", sja1105_dump_ops[blk_idx].name);

		if (!sja1105_dump_ops[blk_idx].dump) {
			printf("dump not implemented, skipping\n");
			continue;
		}

		entry = table->entries;

		for (i = 0; i < table->entry_count; i++) {
			printf("Entry %d:\n", i);
			sja1105_dump_ops[blk_idx].dump(entry);
			entry += table->ops->unpacked_entry_size;
			printf("\n");
		}

		printf("\n");
	}

	sja1105_static_config_free(&config);

	return 0;
}

static void cmd_static_config(struct sja1105_ctx *ctx)
{
	int err;

	printf("Static config:\n");

	err = new_snapshot(ctx, "static-config");
	if (err)
		return;

	err = dump_snapshot(ctx, "static-config");
	if (err)
		return;

	sja1105_dump_static_config(ctx);
}

ssize_t write_exact(int fd, const void *buf, size_t count)
{
	size_t written = 0;
	ssize_t ret;

	do {
		ret = write(fd, buf + written, count - written);
		if (ret <= 0)
			return ret;
		written += ret;
	} while (written != count);

	return written;
}

static int sja1105_save_static_config(struct sja1105_ctx *ctx, const char *file)
{
	struct sja1105_static_config config;
	size_t parsed_len;
	int fd, len;
	int err;

	err = sja1105_static_config_unpack(ctx->snapshot_data, ctx->data_len,
					   &parsed_len, &config);
	if (err)
		return err;

	fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, FILEMODE);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	len = write_exact(fd, ctx->snapshot_data, parsed_len);
	if (len <= 0) {
		perror("write");
		close(fd);
		return len;
	}

	close(fd);

	return 0;
}

static int cmd_static_config_save(struct sja1105_ctx *ctx,
				  const char *file)
{
	int err;

	err = new_snapshot(ctx, "static-config");
	if (err)
		return err;

	err = dump_snapshot(ctx, "static-config");
	if (err)
		return err;

	err = sja1105_save_static_config(ctx, file);
	if (err)
		return err;

	printf("Saved static config to %s\n", file);

	return 0;
}

static int get_info_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct sja1105_ctx *ctx = data;
	const char *driver_name;
	struct nlattr *version;
	int ret;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);

	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_INFO_DRIVER_NAME] ||
	    !tb[DEVLINK_ATTR_INFO_VERSION_FIXED])
		return MNL_CB_ERROR;

	driver_name = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_DRIVER_NAME]);
	if (strcmp(driver_name, "sja1105")) {
		printf("%s/%s is not an sja1105\n", ctx->bus_name,
			ctx->dev_name);
		exit(EXIT_FAILURE);
	}

	mnl_attr_for_each(version, nlh, sizeof(struct genlmsghdr)) {
		struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
		enum sja1105_asic asic;
		const char *ver_value;
		const char *ver_name;
		int err;

		if (mnl_attr_get_type(version) !=
		    DEVLINK_ATTR_INFO_VERSION_FIXED)
			continue;

		err = mnl_attr_parse_nested(version, attr_cb, tb);
		if (err != MNL_CB_OK)
			continue;

		if (!tb[DEVLINK_ATTR_INFO_VERSION_NAME] ||
		    !tb[DEVLINK_ATTR_INFO_VERSION_VALUE])
			continue;

		ver_name = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_VERSION_NAME]);
		ver_value = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_VERSION_VALUE]);

		if (strcmp(ver_name, "asic.id"))
			continue;

		for (asic = 0; asic < __SJA1105_NUM_ASIC; asic++) {
			const struct sja1105_asic_info *info = &sja1105_info[asic];

			if (!strcmp(ver_value, info->name)) {
				ctx->info = info;
				break;
			}
		}

		if (!ctx->info) {
			printf("Unable to parse ASIC version %s\n",
			       ver_value);
			exit(EXIT_FAILURE);
		}
		return MNL_CB_OK;
	}
	return MNL_CB_OK;
}

static void get_info(struct sja1105_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_INFO_GET, flags);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, get_info_cb, ctx);
	if (err) {
		printf("Unable to get devices info\n");
		exit(EXIT_FAILURE);
	}
}

static unsigned int strslashcount(char *str)
{
	unsigned int count = 0;
	char *pos = str;

	while ((pos = strchr(pos, '/'))) {
		count++;
		pos++;
	}
	return count;
}

static int strslashrsplit(char *str, const char **before, const char **after)
{
	char *slash;

	slash = strrchr(str, '/');
	if (!slash)
		return -EINVAL;
	*slash = '\0';
	*before = str;
	*after = slash + 1;
	return 0;
}

int main(int argc, char * argv[])
{
	bool do_static_config_save = false;
	const char *static_config_file;
	bool do_static_config = false;
	struct sja1105_ctx ctx = {0};
	bool have_device = false;
	bool do_list = false;
	bool debug = false;

	static struct option long_options[] = {
		{"static-config",	no_argument,		0,  0 },
		{"static-config-save",	required_argument,	0, 's'},
		{"device",		required_argument,	0, 'd'},
		{"list",		no_argument,		0, 'l'},
		{"debug",		no_argument,		0, 'D'},
		{"help",		no_argument,		0, 'h'},
		{0,			0,			0,  0 }
	};

	while (1) {
		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, "d:lDh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			switch (option_index) {
			case 0:
				do_static_config = true;
				break;
			}
			break;
		case 'd':
			if (strslashcount(optarg) != 1) {
				printf("Wrong devlink identification string format.\n");
				printf("Expected \"bus_name/dev_name\".\n");
				exit(EXIT_FAILURE);
			}
			strslashrsplit(optarg, &ctx.bus_name, &ctx.dev_name);
			have_device = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_FAILURE);
		case 'l':
			do_list = true;
			break;
		case 'D':
			debug = true;
			break;
		case 's':
			do_static_config_save = true;
			static_config_file = optarg;
			break;
		default:
			printf("?? getopt returned character code %d ??\n", c);
			exit(EXIT_FAILURE);
		}
	}

	ctx.nlg = mnlg_socket_open(DEVLINK_GENL_NAME, DEVLINK_GENL_VERSION,
				   debug);
	if (!ctx.nlg) {
		printf("Failed to connect to devlink Netlink\n");
		exit(EXIT_FAILURE);
	}

	if (do_list) {
		list(&ctx);
		exit(EXIT_SUCCESS);
	}

	if (!have_device) {
		first_device(&ctx);
		printf("Using device <%s/%s>\n", ctx.bus_name, ctx.dev_name);
	}

	get_info(&ctx);

	delete_snapshots(&ctx);

	if (do_static_config) {
		cmd_static_config(&ctx);
		delete_snapshots(&ctx);
	}

	if (do_static_config_save) {
		cmd_static_config_save(&ctx, static_config_file);
		delete_snapshots(&ctx);
	}

	mnlg_socket_close(ctx.nlg);
}
