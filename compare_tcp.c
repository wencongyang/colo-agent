/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare tcp packets from master and slave.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/tcp.h>

#include "compare.h"
#include "compare_ipv4.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"
#include "connections.h"
#include "compare_debugfs.h"

bool ignore_ack_packet = 1;
module_param(ignore_ack_packet, bool, 0644);
MODULE_PARM_DESC(ignore_ack_packet, "bypass ack only packet");

bool ignore_retransmitted_packet = 1;
module_param(ignore_retransmitted_packet, bool, 0644);
MODULE_PARM_DESC(ignore_retransmitted_packet, "bypass retransmitted packets");

bool compare_tcp_data = 1;
module_param(compare_tcp_data, bool, 0644);
MODULE_PARM_DESC(compare_tcp_data, "compare tcp data");

bool ignore_tcp_window = 1;
module_param(ignore_tcp_window, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_window, "ignore tcp window");

bool ignore_ack_difference = 1;
module_param(ignore_ack_difference, bool, 0644);
MODULE_PARM_DESC(ignore_ack_difference, "ignore ack difference");

bool ignore_tcp_psh = 1;
module_param(ignore_tcp_psh, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_psh, "ignore tcp psh");

bool ignore_tcp_fin = 1;
module_param(ignore_tcp_fin, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_fin, "ignore tcp fin");

bool ignore_tcp_timestamp = 1;
module_param(ignore_tcp_timestamp, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_timestamp, "ignore tcp timestamp");

bool ignore_tcp_sack = 1;
module_param(ignore_tcp_sack, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_sack, "ignored tcp sack option's difference");

bool ignore_tcp_doff = 1;
module_param(ignore_tcp_doff, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_doff, "ignore tcp doff's difference");

bool ignore_tcp_dlen = 1;
module_param(ignore_tcp_dlen, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_dlen, "ignore tcp payload's length");

//#define DEBUG_COMPARE_MORE_TCP
//#define DEBUG_TCP_DATA

struct tcp_compare_info {
	union {
		struct net_device *dev;
		uint32_t reserved_dev[2];
	};
	uint32_t skb_iif;
	uint32_t snd_nxt;
	uint32_t rcv_nxt;
	uint16_t flags;
	uint16_t window;
	uint32_t timestamp;

	/* only for master */
	uint16_t sent_flags;
	uint16_t sent_window;
	uint32_t sent_rcv_nxt;

	/* add new members here */
	uint32_t reserved[23];
};

#define TCP_CMP_INFO(compare_info) ((struct tcp_compare_info *)compare_info->private_data)

struct tcp_hdr_info {
	uint32_t seq;
	uint32_t end_seq;
	uint32_t ack_seq;
	int length;
	unsigned int flags;
	uint32_t *timestamp;
	uint16_t window;
};

static struct tcp_statistics {
	unsigned long long m_error_packet;
	unsigned long long s_error_packet;
	unsigned long long other_options;
	unsigned long long sack;
	unsigned long long timestamp;
	unsigned long long seq;
	unsigned long long other_flags;
	unsigned long long psh;
	unsigned long long fin;
	unsigned long long window;
	unsigned long long ack_seq;
	unsigned long long doff;
	unsigned long long data;
	unsigned long long data_len;
} statis;

static struct {
	struct dentry *root_entry;
	struct dentry *status_entry;

	struct dentry *m_error_packet_entry;
	struct dentry *s_error_packet_entry;
	struct dentry *other_options_entry;
	struct dentry *sack_entry;
	struct dentry *timestamp_entry;
	struct dentry *seq_entry;
	struct dentry *other_flags_entry;
	struct dentry *psh_entry;
	struct dentry *fin_entry;
	struct dentry *window_entry;
	struct dentry *ack_seq_entry;
	struct dentry *doff_entry;
	struct dentry *data_entry;
	struct dentry *data_len_entry;
} statis_entry;

/* tcp_compare_info & tcp_hdr_info's flags */
#define		SYN		0x01
#define		FIN		0x02
#define		ACK		0x04

/* If this bit is not set, TCP_CMP_INFO() is invalid */
#define		VALID		0x08
#define		VALID_TIMESTAMP	0x10

#define		TCP_CMP_INFO_MASK	0xFFFF

/* tcp_hdr_info's flags */
#define		ERR_SKB		0x010000
#define		RETRANSMIT	0x020000
#define		WIN_UPDATE	0x040000
#define		HAVE_PAYLOAD	0x080000
#define		ACK_UPDATE	0x100000
#define		DUP_ACK		0x200000
#define		OLD_ACK		0x400000

/* FIN and PSH can be ignored */
#define		TCP_CMP_FLAGS_MASK	0xF6

static void debug_print_tcp_header(const unsigned char *n, unsigned int doff)
{
	int i, j;

	pr_warn("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
	pr_warn("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
	pr_warn("HA_compare: %02x %02x %02x %02x\n",
		n[16], n[17], n[18], n[19]);

	/* TCP options */
	for (i = 20; i < doff; i++) {
		if (n[i] == 0)
			break;

		if (n[i] == 1) {
			/* nop */
			pr_warn("HA_compare: nop\n");
			continue;
		}

		pr_warn("HA_compare:");
		for (j = i; j < i + n[i+1]; j++) {
			pr_cont(" %02x", (unsigned int)n[j]);
		}
		pr_cont("\n");

		i += n[i+1] - 1;
	}
}

#ifdef DEBUG_TCP_DATA
static void debug_print_tcp_payload(const void *payload, const int length)
{
	int i;
	const char *n = payload;

	for (i = 0; i < length / 8; i += 8) {
		pr_warn("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
			n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
		n += 8;
	}

	if (length % 8 != 0) {
		pr_warn("HA_compare:");
		for (i = 0; i < length % 8; i++)
			pr_cont(" %02x", n[i]);
		pr_cont("\n");
	}
}
#else
static void debug_print_tcp_payload(const void *payload, const int length)
{
}
#endif

static void debug_print_tcp(const struct compare_info *info, const void *data,
			    int length)
{
	unsigned int ack, seq;
	unsigned int doff;
	unsigned short src_port, dst_port;
	const struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_cinfo;

	src_port = ntohs(tcp->source);
	dst_port = ntohs(tcp->dest);
	ack = ntohl(tcp->ack_seq);
	seq = ntohl(tcp->seq);
	pr_warn("HA_compare:[TCP] src=%u, dst=%u, seq = %u,"
		" ack=%u\n", src_port, dst_port, seq,
		ack);

	tcp_cinfo = TCP_CMP_INFO(info);
	if (tcp_cinfo->flags & VALID)
		pr_warn("HA_compare: snd_nxt: %u, rcv_nxt: %u\n",
			tcp_cinfo->snd_nxt, tcp_cinfo->rcv_nxt);

	doff = tcp->doff * 4;
	debug_print_tcp_header(data, doff);

	length -= doff;
	debug_print_tcp_payload((const char *)data + doff, length);
}

static void
update_tcp_window(struct tcphdr *tcp, struct sk_buff *skb, uint16_t new_window)
{
	uint16_t old_window = ntohs(tcp->window);

	if (new_window >= old_window)
		return;

	tcp->window = htons(new_window);

	inet_proto_csum_replace2(&tcp->check, skb, htons(old_window),
				 tcp->window, 0);
}

static void
update_tcp_ackseq(struct tcphdr *tcp, struct sk_buff *skb, uint32_t new_ack)
{
	uint32_t old_ack = ntohl(tcp->ack_seq);

	if (!before(new_ack, old_ack))
		return;

	tcp->ack_seq = htonl(new_ack);

	inet_proto_csum_replace4(&tcp->check, skb, htonl(old_ack),
				 tcp->ack_seq, 0);
}

static void
update_tcp_psh(struct tcphdr *tcp, struct sk_buff *skb)
{
	uint16_t old_value = ((uint16_t *)tcp)[6];
	uint16_t new_value;

	tcp->psh = 1;
	new_value = ((uint16_t *)tcp)[6];
	inet_proto_csum_replace2(&tcp->check, skb, old_value, new_value, 0);
}

static void
update_tcp_fin(struct tcphdr *tcp, struct sk_buff *skb, bool clear)
{
	uint16_t old_value = ((uint16_t *)tcp)[6];
	uint16_t new_value;
	uint32_t old_seq = tcp->seq;

	tcp->fin = !clear;
	new_value=((uint16_t *)tcp)[6];

	inet_proto_csum_replace2(&tcp->check, skb, old_value, new_value, 0);
	if (clear)
		return;

	/* update the seq number */
	tcp->seq = htonl(ntohl(old_seq) - 1);
	inet_proto_csum_replace4(&tcp->check, skb, old_seq, tcp->seq, 0);
}

static void *get_next_opt_by_kind(void *opts, void *end, uint8_t kind);
/*
 * if we generate a new packet for master, the old timestamp is from
 * slave packet. Use the timestamp from master packet instead of it.
 */
static void
update_tcp_timestamp(struct tcphdr *tcp, struct sk_buff *skb,
		     uint32_t new_timestamp)
{
	uint32_t *old_timestamp =
		get_next_opt_by_kind(tcp + 1, (char *)tcp + tcp->doff * 4,
				     TCPOPT_TIMESTAMP);

	if (!old_timestamp)
		return;

	old_timestamp = (uint32_t *)((char *)old_timestamp + 2);

	if (ntohl(*old_timestamp) == new_timestamp)
		return;

	inet_proto_csum_replace4(&tcp->check, skb, *old_timestamp,
				 htonl(new_timestamp), 0);
	*old_timestamp = htonl(new_timestamp);
}

static void
clear_tcp_sack(struct tcphdr *tcp, struct sk_buff *skb)
{
	uint8_t *sack =
		get_next_opt_by_kind(tcp + 1, (char *)tcp + tcp->doff * 4,
				     TCPOPT_SACK);
	uint16_t old_value, new_value;

	if (!sack)
		return;

	old_value = *(uint16_t*)sack;
	*sack = TCPOPT_EOL;
	new_value = *(uint16_t*)sack;
	inet_proto_csum_replace2(&tcp->check, skb, old_value, new_value, 0);
}

static void
get_tcp_hdr_info(struct tcphdr *tcp, int length,
		 struct tcp_compare_info *tcp_cinfo,
		 struct tcp_hdr_info *tcp_hinfo)
{
	length -= tcp->doff * 4;

	tcp_hinfo->seq = ntohl(tcp->seq);
	tcp_hinfo->end_seq = tcp_hinfo->seq;
	tcp_hinfo->length = length;
	tcp_hinfo->window = ntohs(tcp->window);

	if (unlikely(length < 0)) {
		tcp_hinfo->flags |= ERR_SKB;
		return;
	}

	if (unlikely(tcp->fin && tcp->syn)) {
		tcp_hinfo->flags |= ERR_SKB;
		return;
	}

	tcp_hinfo->flags = 0;
	if (tcp->fin) {
		tcp_hinfo->flags |= FIN;
		tcp_hinfo->length++;
	}

	if (tcp->syn) {
		tcp_hinfo->flags |= SYN;
		tcp_hinfo->length++;
	}

	if (tcp->ack) {
		tcp_hinfo->flags |= ACK;
		tcp_hinfo->ack_seq = ntohl(tcp->ack_seq);
	}

	tcp_hinfo->end_seq += tcp_hinfo->length;

	/* timestamp */
	tcp_hinfo->timestamp =
		get_next_opt_by_kind(tcp + 1, (char *)tcp + tcp->doff * 4,
				     TCPOPT_TIMESTAMP);

	if (tcp_hinfo->timestamp)
		tcp_hinfo->timestamp =
			(uint32_t *)((char *)tcp_hinfo->timestamp + 2);

	if (length > 0)
		tcp_hinfo->flags |= HAVE_PAYLOAD;

	if (tcp->rst)
		/*
		 * rst packet, not ack update, win update, or retransmitted
		 * packet
		 */
		return;

	/*
	 * This packet is the first packet, and we can not check whether it is
	 * an ack update, win update, or retransmitted packet.
	 */
	if (!(tcp_cinfo->flags & VALID))
		return;

	/* TCP only retransmits data/SIN/FYN */
	if (tcp_hinfo->length > 0) {
		/*
		 * Retransmitted packet:
		 *  1. end_seq is before snd_nxt
		 *  2. end_seq is equal to snd_nxt, and seq is before snd_nxt
		 */
		if (before(tcp_hinfo->end_seq, tcp_cinfo->snd_nxt) ||
		    (tcp_hinfo->end_seq == tcp_cinfo->snd_nxt &&
		     before(tcp_hinfo->seq, tcp_cinfo->snd_nxt)))
			tcp_hinfo->flags |= RETRANSMIT;
	}

	/* check window update */
	if (tcp_hinfo->window > tcp_cinfo->window)
		tcp_hinfo->flags |= WIN_UPDATE;

	if ((tcp_hinfo->flags & ACK) &&
	    after(tcp_hinfo->ack_seq, tcp_cinfo->rcv_nxt))
		tcp_hinfo->flags |= ACK_UPDATE;

	if ((tcp_hinfo->flags & ACK_UPDATE) || !(tcp_hinfo->flags & ACK))
		return;

	if (tcp_hinfo->length > 0)
		return;

	/* check dup ack */
	if (tcp_hinfo->ack_seq == tcp_cinfo->rcv_nxt) {
		tcp_hinfo->flags |= DUP_ACK;
	} else {
		tcp_hinfo->flags |= OLD_ACK;

		/* old ack's window is older, ignore it */
		tcp_hinfo->flags &= ~WIN_UPDATE;
	}
}

static void
update_tcp_sent_info(struct tcp_compare_info *tcp_cinfo, struct tcphdr *tcp)
{
	if (tcp->fin)
		tcp_cinfo->sent_flags |= FIN;
	else if (tcp->syn)
		tcp_cinfo->sent_flags |= ~FIN;

	tcp_cinfo->sent_window = ntohs(tcp->window);
	tcp_cinfo->sent_rcv_nxt = ntohl(tcp->ack_seq);
}

static void
update_tcp_compare_info(struct tcp_compare_info *tcp_cinfo,
			struct tcp_hdr_info *tcp_hinfo,
			struct sk_buff *skb)
{
	if (tcp_hinfo->flags & ACK_UPDATE || !(tcp_cinfo->flags & VALID))
		tcp_cinfo->rcv_nxt = tcp_hinfo->ack_seq;

	if (!(tcp_hinfo->flags & OLD_ACK))
		tcp_cinfo->window = tcp_hinfo->window;

	if (tcp_hinfo->timestamp) {
		uint32_t timestamp = ntohl(*tcp_hinfo->timestamp);
		if (tcp_cinfo->flags & VALID_TIMESTAMP) {
			if (after(timestamp, tcp_cinfo->timestamp))
				tcp_cinfo->timestamp = timestamp;
		} else {
			tcp_cinfo->timestamp = timestamp;
			tcp_cinfo->flags |= VALID_TIMESTAMP;
		}
	}

	if (!(tcp_hinfo->flags & RETRANSMIT)) {
		uint16_t old_flags = tcp_cinfo->flags;
		tcp_cinfo->flags = (tcp_hinfo->flags & TCP_CMP_INFO_MASK) | VALID;

		/*
		 * FIN means we don't send any data more, but we can receive
		 * data. So we should not overwrite this FIN flags.
		 */
		if (old_flags & FIN && tcp_hinfo->length == 0)
			tcp_cinfo->flags |= FIN;

		if (old_flags & VALID_TIMESTAMP)
			tcp_cinfo->flags |= VALID_TIMESTAMP;
	}

	if (!(tcp_hinfo->flags & RETRANSMIT) && tcp_hinfo->length > 0)
		tcp_cinfo->snd_nxt = tcp_hinfo->end_seq;

	tcp_cinfo->dev = skb->dev;
	tcp_cinfo->skb_iif = skb->skb_iif;
}

static void tcp_update_packet(struct compare_info *m_cinfo,
			      struct compare_info *s_cinfo,
			      uint32_t ret)
{
	struct tcp_compare_info *m_tcp_cinfo = TCP_CMP_INFO(m_cinfo);
	struct tcp_compare_info *s_tcp_cinfo = TCP_CMP_INFO(s_cinfo);
	struct tcphdr *m_tcp = m_cinfo->tcp;
	struct tcphdr *s_tcp = s_cinfo->tcp;
	struct sk_buff *m_skb = m_cinfo->skb;

	if (!(ret & BYPASS_MASTER))
		return;

	/* PSH */
	if (!s_cinfo->skb)
		goto skip_fin;
	if ((ret & SAME_PACKET) != SAME_PACKET)
		goto skip_psh;
	if (m_tcp->psh != s_tcp->psh && !m_tcp->psh)
		update_tcp_psh(m_tcp, m_skb);

skip_psh:
	/* FIN */
	if (m_tcp_cinfo->flags & FIN && !m_tcp->fin &&
	    s_tcp->fin) {
		/* add the flags FIN again */
		update_tcp_fin(m_tcp, m_skb, false);
	} else if (m_tcp->fin &&
		   !(m_tcp_cinfo->flags & FIN) &&
		   !s_tcp->fin) {
		/* clear the flags FIN */
		update_tcp_fin(m_tcp, m_skb, true);
	}

skip_fin:
	if (ret & CLONED_PACKET) {
		update_tcp_ackseq(m_tcp, m_skb, m_tcp_cinfo->rcv_nxt);
		update_tcp_window(m_tcp, m_skb, m_tcp_cinfo->window);
	} else {
		update_tcp_ackseq(m_tcp, m_skb, s_tcp_cinfo->rcv_nxt);
		update_tcp_window(m_tcp, m_skb, s_tcp_cinfo->window);
	}

	/*
	 * TODO: if the packets from master and slave contain the same sack, no
	 * need to clear it.
	 */
	clear_tcp_sack(m_tcp, m_skb);

	/*
	 * we don't touch the packet from slave, so no need to save
	 * sent info for slave
	 */
	update_tcp_sent_info(m_tcp_cinfo, m_tcp);

	update_tcp_timestamp(m_tcp, m_skb, m_tcp_cinfo->timestamp);
}

static uint32_t check_ack_only_packet(uint32_t m_flags, uint32_t s_flags,
				      bool m_fin, bool s_fin)
{
	uint32_t ret = 0;

	if (m_fin)
		m_flags |= FIN;
	if (s_fin)
		s_flags |= FIN;

	/*
	 * 4 types of packet:
	 *   1. FIN
	 *   2. HAVE_PAYLOAD
	 *   3. FIN + HAVE_PAYLOAD
	 *   4. Ack only
	 *
	 * So there are 16 cases to be handled:
	 *     Master               Slaver              Return value
	 *     FIN+HAVE_PAYLOAD     FIN                 CHECKPOINT
	 *     FIN+HAVE_PAYLOAD     Ack only            DROP_SLAVER
	 *     FIN                  FIN+HAVE_PAYLOAD    CHECKPOINT
	 *     FIN                  HAVE_PAYLOAD        CHECKPOINT
	 *     HAVE_PAYLOAD         FIN                 CHECKPOINT
	 *     HAVE_PAYLOAD         Ack only            DROP_SLAVER
	 *     Ack only             FIN+HAVE_PAYLOAD    BYPASS_MASTER
	 *     Ack only             HAVE_PAYLOAD        BYPASS_MASTER
	 *
	 *     FIN+HAVE_PAYLOAD     FIN+HAVE_PAYLOAD    0
	 *     FIN+HAVE_PAYLOAD     HAVE_PAYLOAD        0(FIN may be cleared)
	 *     FIN                  FIN                 0
	 *     FIN                  Ack only            0(FIN may be cleared)
	 *     HAVE_PAYLOAD         FIN+HAVE_PAYLOAD    0(FIN will be remembered)
	 *     HAVE_PAYLOAD         HAVE_PAYLOAD        0
	 *     Ack only             FIN                 0(FIN will be remembered)
	 *     Ack only             Ack only            0
	 */

	/* case 9-16 */
	if ((m_flags & HAVE_PAYLOAD) == (s_flags & HAVE_PAYLOAD))
		return 0;

	/* case 1,3-5 */
	if (((m_flags & FIN) && (s_flags & HAVE_PAYLOAD)) ||
	    ((m_flags & HAVE_PAYLOAD) && (s_flags & FIN))) {
		statis.fin++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	/* case 2,6-8 */
	if (m_flags & HAVE_PAYLOAD)
		ret |= DROP_SLAVER;
	if (s_flags & HAVE_PAYLOAD)
		ret |= BYPASS_MASTER;
	return ret;
}

static void *get_next_opt(void *opts, void *end)
{
	uint8_t opcode, opsize;
	uint8_t *optr = opts;
	long length = end - opts;

	/* for get_next_opt_by_kind(NULL, ...) */
	if (!opts)
		return NULL;

	while (length > 0) {
		opcode = *optr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			if (length == 1)
				return NULL;

			opsize = *optr;
			if (opsize < 2 || opsize > length)
				return NULL;
			return optr - 1;
		}
	}

	return NULL;
}

static void *get_next_opt_by_kind(void *opts, void *end, uint8_t kind)
{
	uint8_t *optr = get_next_opt(opts, end);
	uint8_t opcode, opsize;

	while (optr != NULL) {
		opcode = *optr;
		opsize = *(optr + 1);
		if (opcode == kind)
			return optr;

		optr += opsize;
		optr = get_next_opt(optr, end);
	}

	return NULL;
}

static void update_statis_options(uint8_t opcode)
{
	switch(opcode) {
	case TCPOPT_SACK:
		statis.sack++;
		break;
	case TCPOPT_TIMESTAMP:
		statis.timestamp++;
		break;
	default:
		statis.other_options++;
		break;
	}
}

static uint32_t compare_opt(uint8_t *m_optr, uint8_t *s_optr)
{
	uint8_t m_opcode, m_opsize;
	uint8_t s_opcode, s_opsize;
	uint32_t ret;

	m_opcode = *m_optr++;
	m_opsize = *m_optr++;
	s_opcode = *s_optr++;
	s_opsize = *s_optr++;

	BUG_ON(m_opcode != s_opcode);
	if (m_opsize != s_opsize) {
		update_statis_options(m_opcode);
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	if (m_opsize == 2)
		return 0;

	if (m_opcode != TCPOPT_TIMESTAMP || !ignore_tcp_timestamp) {
		ret = memcmp(m_optr, s_optr, m_opsize - 2);
		if (ret) {
			update_statis_options(m_opcode);
			ret = CHECKPOINT | UPDATE_COMPARE_INFO;
		}
		return ret;
	}

	return 0;
}

static uint32_t
compare_tcp_options(void *m_opts, void *m_opts_end, void *s_opts, void *s_opts_end)
{
	void *m_opt = get_next_opt(m_opts, m_opts_end);
	void *s_opt = get_next_opt(s_opts, s_opts_end);
	uint8_t opcode, opsize;
	uint8_t *m_optr = m_opt;
	uint8_t *s_optr = s_opt;
	uint32_t ret;

	if (!m_opt && !s_opt)
		return 0;

	while (m_optr != NULL) {
		opcode = *m_optr;
		opsize = *(m_optr + 1);

		if (ignore_tcp_sack && opcode == TCPOPT_SACK)
			goto skip;

		s_optr = get_next_opt_by_kind(s_opt, s_opts_end, opcode);
		if (!s_optr) {
			update_statis_options(opcode);
			return CHECKPOINT | UPDATE_COMPARE_INFO;
		}

		ret = compare_opt(m_optr, s_optr);
		if (ret)
			return ret;

skip:
		m_optr += opsize;
		m_optr = get_next_opt(m_optr, m_opts_end);
	}

	s_optr = s_opt;
	while (s_optr != NULL) {
		opcode = *s_optr;
		opsize = *(s_optr + 1);

		if (ignore_tcp_sack && opcode == TCPOPT_SACK)
			goto skip2;

		m_optr = get_next_opt_by_kind(m_opt, m_opts_end, opcode);
		if (!m_optr) {
			update_statis_options(opcode);
			return CHECKPOINT | UPDATE_COMPARE_INFO;
		}

skip2:
		s_optr += opsize;
		s_optr = get_next_opt(s_optr, s_opts_end);
	}

	return 0;
}

#ifdef DEBUG_COMPARE_MORE_TCP
#define RETURN(value)			\
	do {				\
		saved_ret = value;	\
	} while (0)
#else
#define RETURN(value)			\
	do {				\
		return value;		\
	} while (0)
#endif

#define CHECK_BEFORE_FINISH		\
	do {				\
		if (saved_ret)		\
			goto out;	\
	} while (0)

#define RETURN_FINISH(value)			\
	do {					\
		if (saved_ret)			\
			return saved_ret;	\
		else				\
			return value;		\
	} while (0)

static int
tcp_compare_header(struct compare_info *m_cinfo, struct compare_info *s_cinfo,
		   struct tcp_hdr_info *m_tcp_hinfo,
		   struct tcp_hdr_info *s_tcp_hinfo)
{
	uint8_t m_flags, s_flags;
	uint32_t ret = 0, saved_ret = 0;

#define compare(elem)								\
	do {									\
		if (unlikely(m_cinfo->tcp->elem != s_cinfo->tcp->elem)) {	\
			pr_warn("HA_compare: tcp header's %s is different\n",	\
				#elem);						\
			UPDATE_STATIS(elem);					\
			RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);		\
		}								\
	} while (0)

#define UPDATE_STATIS(elem)
	/* source port and dest port*/
	compare(source);
	compare(dest);
#undef UPDATE_STATIS

#define UPDATE_STATIS(elem)	statis.elem++

	if (m_tcp_hinfo->flags & ERR_SKB) {
		statis.m_error_packet++;
		ret |= BYPASS_MASTER;
	}
	if (s_tcp_hinfo->flags & ERR_SKB) {
		statis.s_error_packet++;
		ret |= DROP_SLAVER;
	}
	if (ret)
		return ret;

	if (ignore_retransmitted_packet) {
		if (m_tcp_hinfo->flags & RETRANSMIT)
			ret |= BYPASS_MASTER;
		if (s_tcp_hinfo->flags & RETRANSMIT)
			ret |= DROP_SLAVER;
		if (ret)
			goto out;
	}

	/* seq */
	if ((TCP_CMP_INFO(m_cinfo)->flags & FIN) !=
	    (TCP_CMP_INFO(s_cinfo)->flags & FIN)) {
		uint32_t m_seq = ntohl(m_cinfo->tcp->seq);
		uint32_t s_seq = ntohl(s_cinfo->tcp->seq);

		if (TCP_CMP_INFO(m_cinfo)->flags & FIN)
			m_seq -= 1;
		if (TCP_CMP_INFO(s_cinfo)->flags & FIN)
			s_seq -= 1;
		if (unlikely(m_seq != s_seq) && !ignore_tcp_dlen) {
			pr_warn("HA_compare: tcp header's seq is different\n");
			statis.seq++;
			RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);
		}
	} else if (!ignore_tcp_dlen || (m_tcp_hinfo->flags & SYN))
		compare(seq);

	/* flags */
	m_flags = *(uint8_t *)((char *)m_cinfo->tcp + 13);
	s_flags = *(uint8_t *)((char *)s_cinfo->tcp + 13);
	if ((m_flags & TCP_CMP_FLAGS_MASK) != (s_flags & TCP_CMP_FLAGS_MASK)) {
		pr_warn("HA_compare: tcp header's flags is different\n");
		statis.other_flags++;
		RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);
	}

	if (!ignore_tcp_psh) {
		if (m_cinfo->tcp->psh != s_cinfo->tcp->psh) {
			pr_warn("HA_compare: tcp header's flags is different\n");
			statis.psh++;
			RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);
		}
	}

	if (!ignore_tcp_fin) {
		if (m_cinfo->tcp->fin != s_cinfo->tcp->fin) {
			pr_warn("HA_compare: tcp header's flags is different\n");
			statis.fin++;
			RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);
		}
	}

	if (ignore_ack_packet) {
		ret = check_ack_only_packet(m_tcp_hinfo->flags,
					    s_tcp_hinfo->flags,
					    TCP_CMP_INFO(m_cinfo)->flags & FIN,
					    TCP_CMP_INFO(s_cinfo)->flags & FIN);
		if (ret)
			goto out;
	}

	/* data offset */
	if (!ignore_tcp_doff)
		compare(doff);

	ret = compare_tcp_options(m_cinfo->ip_data + sizeof(struct tcphdr),
				  m_cinfo->ip_data + m_cinfo->tcp->doff * 4,
				  s_cinfo->ip_data + sizeof(struct tcphdr),
				  s_cinfo->ip_data + s_cinfo->tcp->doff * 4);
	if (ret) {
		pr_warn("HA_compare: tcp header's options are different\n");
		RETURN(CHECKPOINT | UPDATE_COMPARE_INFO);
	}

	/* tcp window size */
	if (!ignore_tcp_window)
		compare(window);

	/* Acknowledgment Number */
	if (m_cinfo->tcp->ack && !ignore_ack_difference) {
		compare(ack_seq);
	}

#undef compare

	CHECK_BEFORE_FINISH;

	if (ignore_tcp_doff)
		return SAME_PACKET | UPDATE_MASTER_PACKET | IGNORE_LEN;
	else
		return SAME_PACKET | UPDATE_MASTER_PACKET;

out:
	/* Retransmitted packet or ack only packet */
	if (ret & BYPASS_MASTER)
		ret |= UPDATE_MASTER_PACKET;

	if ((ret & SAME_PACKET) == SAME_PACKET)
		ret |= IGNORE_LEN;

	RETURN_FINISH(ret);
}

/* The caller call this function only when tcp_compare_header() returns SAME_PACKET */
static bool
tcp_need_compare_data(struct tcp_hdr_info *m_tcp_hinfo,
		      struct tcp_hdr_info *s_tcp_hinfo)
{
	/*
	 * If m_tcp_hinfo->flags has ERR_SKB, s_tcp_hinfo->flags also
	 * has ERR_SKB.
	 */
	if (m_tcp_hinfo->flags & ERR_SKB)
		return false;

	if (m_tcp_hinfo->flags & RETRANSMIT && s_tcp_hinfo->flags & RETRANSMIT)
		return false;

	/*
	 * ignore_retransmitted_packet is 0, and ignore_tcp_dlen is 1.
	 *
	 * We have compared the data or compare_tcp_data is 0,
	 * so return false.
	 *
	 * In this case, the caller should return BYPASS_MASTER or DROP_SLAVER.
	 */
	if (m_tcp_hinfo->flags & RETRANSMIT || s_tcp_hinfo->flags & RETRANSMIT)
		return false;

	if (!(m_tcp_hinfo->flags & HAVE_PAYLOAD) &&
	    !(s_tcp_hinfo->flags & HAVE_PAYLOAD))
		return false;

	/*
	 * In this case, the caller should check the dlen
	 * if ignore_tcp_dlen is 1.
	 */
	if ((m_tcp_hinfo->flags & HAVE_PAYLOAD) &&
	    (s_tcp_hinfo->flags & HAVE_PAYLOAD))
		return compare_tcp_data;

	/*
	 * ignore_ack_packet is 0, one packet has payload while the other packet
	 * doesn't have. In this case, do a new checkpoint.
	 */
	return true;
}

static uint32_t tcp_compare_packet(struct compare_info *m_cinfo,
				   struct compare_info *s_cinfo)
{
	int m_len, s_len;
	uint32_t ret, saved_ret;
	struct tcp_hdr_info m_tcp_hinfo, s_tcp_hinfo;

	get_tcp_hdr_info(m_cinfo->tcp, m_cinfo->length, TCP_CMP_INFO(m_cinfo),
			 &m_tcp_hinfo);
	get_tcp_hdr_info(s_cinfo->tcp, s_cinfo->length, TCP_CMP_INFO(s_cinfo),
			 &s_tcp_hinfo);

	ret = tcp_compare_header(m_cinfo, s_cinfo, &m_tcp_hinfo, &s_tcp_hinfo);
	if ((ret & SAME_PACKET) != SAME_PACKET)
		goto update_cinfo;

	if (!tcp_need_compare_data(&m_tcp_hinfo, &s_tcp_hinfo))
		goto update_cinfo;

	saved_ret = ret;

	m_len = m_cinfo->length - m_cinfo->tcp->doff * 4;
	s_len = s_cinfo->length - s_cinfo->tcp->doff * 4;
	if (!ignore_tcp_dlen && (m_len != s_len)) {
		pr_warn("HA_compare: tcp data's len is different\n");
		statis.data_len++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	m_cinfo->tcp_data = m_cinfo->ip_data + m_cinfo->tcp->doff * 4;
	s_cinfo->tcp_data = s_cinfo->ip_data + s_cinfo->tcp->doff * 4;
	if (ignore_tcp_dlen) {
		if (before(m_tcp_hinfo.seq, s_tcp_hinfo.seq)){
			m_cinfo->tcp_data += s_tcp_hinfo.seq - m_tcp_hinfo.seq;
			m_len -= s_tcp_hinfo.seq - m_tcp_hinfo.seq;
		} else {
			s_cinfo->tcp_data += m_tcp_hinfo.seq - s_tcp_hinfo.seq;
			s_len -= m_tcp_hinfo.seq - s_tcp_hinfo.seq;
		}

		if (m_len < s_len) {
			/*
			 * The packet from slave contains some data that is not
			 * compared this time
			 */
			saved_ret &= ~DROP_SLAVER;
		} else if (m_len > s_len) {
			/*
			 * The packet from master contains some data that is not
			 * compared this time
			 */
			saved_ret &= ~(BYPASS_MASTER | UPDATE_MASTER_PACKET);
		}
		m_len = min(m_len, s_len);
	}
	ret = default_compare_data(m_cinfo->tcp_data, s_cinfo->tcp_data, m_len);
	if (ret & CHECKPOINT) {
		pr_warn("HA_compare: tcp data is different\n");
		statis.data++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}
	ret = saved_ret;

update_cinfo:
	if (ret & BYPASS_MASTER) {
		update_tcp_compare_info(TCP_CMP_INFO(m_cinfo), &m_tcp_hinfo,
					m_cinfo->skb);
	}
	if (ret & DROP_SLAVER) {
		update_tcp_compare_info(TCP_CMP_INFO(s_cinfo), &s_tcp_hinfo,
					s_cinfo->skb);
	}
	return ret;
}

#define IP_DATA(skb)	(void *)(ip_hdr(skb)->ihl * 4 + (char *)ip_hdr(skb))

static struct tcphdr *get_tcphdr(struct sk_buff *skb)
{
	struct tcphdr *tcph, _tcph;
	int size, ret;

	if (FRAG_CB(skb)->len < sizeof(struct tcphdr)) {
		ret = ipv4_copy_transport_head(&_tcph, skb,
					       sizeof(struct tcphdr));
		if (ret)
			return NULL;

		tcph = &_tcph;
	} else {
		tcph = IP_DATA(skb);
	}

	size = tcph->doff * 4;
	tcph = kmalloc(size, GFP_ATOMIC);
	if (!tcph)
		return NULL;

	ret = ipv4_copy_transport_head(tcph, skb, size);
	if (ret) {
		kfree(tcph);
		return NULL;
	}

	return tcph;
}

static uint32_t
tcp_compare_payload(struct compare_info *m_cinfo,
		    struct compare_info *s_cinfo,
		    struct tcp_hdr_info *m_tcp_hinfo,
		    struct tcp_hdr_info *s_tcp_hinfo,
		    uint32_t *saved_ret)
{
	struct sk_buff *m_head = m_cinfo->skb, *s_head = s_cinfo->skb;
	int m_off, s_off;
	int m_dlen, s_dlen;
	uint32_t ret;

	m_off = m_cinfo->tcp->doff * 4;
	s_off = s_cinfo->tcp->doff * 4;
	m_dlen = m_cinfo->length - m_off;
	s_dlen = s_cinfo->length - s_off;

	if (ignore_tcp_dlen) {
		if (before(m_tcp_hinfo->seq, s_tcp_hinfo->seq)) {
			m_off += s_tcp_hinfo->seq - m_tcp_hinfo->seq;
			m_dlen -= s_tcp_hinfo->seq - m_tcp_hinfo->seq;
		} else {
			s_off += m_tcp_hinfo->seq - s_tcp_hinfo->seq;
			s_dlen -= m_tcp_hinfo->seq - s_tcp_hinfo->seq;
		}

		if (m_dlen < s_dlen) {
			/*
			 * The packet from slave contains some data that is not
			 * compared this time
			 */
			*saved_ret &= ~DROP_SLAVER;
		} else if (m_dlen > s_dlen) {
			/*
			 * The packet from master contains some data that is not
			 * compared this time
			 */
			*saved_ret &= ~(BYPASS_MASTER | UPDATE_MASTER_PACKET);
		}
	} else if (m_dlen != s_dlen) {
		statis.data_len++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	ret = ipv4_transport_compare_fragment(m_head, s_head, m_off, s_off,
					      min(m_dlen, s_dlen));
	if (ret & CHECKPOINT)
		statis.data++;

	return ret;
}

static uint32_t
tcp_compare_fragment(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	struct sk_buff *m_skb = m_cinfo->skb;
	struct sk_buff *s_skb = s_cinfo->skb;
	struct tcphdr *m_tcp = NULL, *old_m_tcp = NULL;
	struct tcphdr *s_tcp = NULL, *old_s_tcp = NULL;
	uint32_t ret = CHECKPOINT | UPDATE_COMPARE_INFO, saved_ret;
	struct tcp_hdr_info m_tcp_hinfo, s_tcp_hinfo;

	if (FRAG_CB(m_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(m_skb)->len < m_cinfo->tcp->doff * 4) {
		old_m_tcp = m_cinfo->tcp;
		m_cinfo->tcp = m_tcp = get_tcphdr(m_skb);
		if (!m_tcp) {
			statis.m_error_packet++;
			goto out;
		}
	}

	if (FRAG_CB(s_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(s_skb)->len < s_cinfo->tcp->doff * 4) {
		old_s_tcp = s_cinfo->tcp;
		s_cinfo->tcp = s_tcp = get_tcphdr(s_skb);
		if (!s_tcp) {
			statis.s_error_packet++;
			goto out;
		}
	}

	get_tcp_hdr_info(m_cinfo->tcp, m_cinfo->length, TCP_CMP_INFO(m_cinfo),
			 &m_tcp_hinfo);
	get_tcp_hdr_info(s_cinfo->tcp, s_cinfo->length, TCP_CMP_INFO(s_cinfo),
			 &s_tcp_hinfo);

	ret = tcp_compare_header(m_cinfo, s_cinfo, &m_tcp_hinfo, &s_tcp_hinfo);
	if ((ret & SAME_PACKET) != SAME_PACKET)
		goto update_cinfo;

	if (!tcp_need_compare_data(&m_tcp_hinfo, &s_tcp_hinfo))
		goto update_cinfo;

	saved_ret = ret;

	ret = tcp_compare_payload(m_cinfo, s_cinfo, &m_tcp_hinfo, &s_tcp_hinfo,
				  &saved_ret);
	if (ret & CHECKPOINT)
		goto out;

	ret = saved_ret;

update_cinfo:
	if (ret & BYPASS_MASTER) {
		update_tcp_compare_info(TCP_CMP_INFO(m_cinfo), &m_tcp_hinfo,
					m_cinfo->skb);
	}
	if (ret & DROP_SLAVER) {
		update_tcp_compare_info(TCP_CMP_INFO(s_cinfo), &s_tcp_hinfo,
					s_cinfo->skb);
	}

out:
	if (m_tcp)
		kfree(m_tcp);
	if (s_tcp)
		kfree(s_tcp);
	if (old_m_tcp)
		m_cinfo->tcp = old_m_tcp;
	if (old_s_tcp)
		s_cinfo->tcp = old_s_tcp;

	return ret;
}

static struct sk_buff *create_new_skb(struct sk_buff *skb,
				      struct compare_info *cinfo)
{
	struct sk_buff *new_skb;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	new_skb = skb_copy(skb, GFP_ATOMIC);
	if (!new_skb)
		return NULL;

	new_skb->dev = TCP_CMP_INFO(cinfo)->dev;
	new_skb->skb_iif = TCP_CMP_INFO(cinfo)->skb_iif;
	cinfo->skb = new_skb;

	eth = (struct ethhdr *)new_skb->data;
	if (unlikely(ntohs(eth->h_proto) != ETH_P_IP))
		goto err;

	ip = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
	if (unlikely(ip->protocol != IPPROTO_TCP))
		goto err;

	tcp = (struct tcphdr *)((char *)ip + ip->ihl * 4);

	cinfo->eth = eth;
	cinfo->ip = ip;
	cinfo->tcp = tcp;

	return new_skb;

err:
	pr_warn("OOPS, origin skb is not TCP packet.\n");
	kfree_skb(new_skb);
	return NULL;
}

static void
update_tcp_hdr_flags(struct compare_info *cinfo,
		     struct compare_info *other_cinfo,
		     struct tcp_hdr_info *tcp_hinfo)
{
	struct tcp_compare_info *tcp_cinfo = TCP_CMP_INFO(cinfo);
	struct tcp_compare_info *other_tcp_cinfo = TCP_CMP_INFO(other_cinfo);

	/* more check for window update */
	if (tcp_hinfo->flags & WIN_UPDATE)
		if (tcp_cinfo->window >= other_tcp_cinfo->window)
			tcp_hinfo->flags &= ~WIN_UPDATE;

	/* more check for ack_seq update and dup_ack */
	if (tcp_hinfo->flags & (ACK_UPDATE | DUP_ACK))
		if (!after(other_tcp_cinfo->rcv_nxt, tcp_cinfo->rcv_nxt))
			tcp_hinfo->flags &= ~(ACK_UPDATE | DUP_ACK);
}

static uint32_t
tcp_compare_one_packet(struct compare_info *m_cinfo,
		       struct compare_info *s_cinfo)
{
	struct sk_buff *skb, *new_skb = NULL;
	struct compare_info *cinfo, *other_cinfo;
	struct tcp_hdr_info tcp_hinfo;
	uint32_t ret = 0;

	/* compare one packet is only for tcp ack, window and fin */
	if (!ignore_ack_packet && !ignore_ack_difference &&
	    !ignore_tcp_window && !ignore_tcp_fin)
		return 0;

	if (m_cinfo->skb) {
		cinfo = m_cinfo;
		other_cinfo = s_cinfo;
		ret |= BYPASS_MASTER;
	} else if (s_cinfo->skb) {
		cinfo = s_cinfo;
		other_cinfo = m_cinfo;
		ret |= DROP_SLAVER;
	} else
		BUG();

	skb = cinfo->skb;
	get_tcp_hdr_info(cinfo->tcp, cinfo->length, TCP_CMP_INFO(cinfo),
			 &tcp_hinfo);

	if (unlikely(tcp_hinfo.flags & ERR_SKB))
		return ret;

	if (!ignore_ack_difference && tcp_hinfo.flags & ACK_UPDATE)
		return 0;

	if (!ignore_tcp_window && tcp_hinfo.flags & WIN_UPDATE)
		return 0;

	/* more check for window and ack_seq update */
	update_tcp_hdr_flags(cinfo, other_cinfo, &tcp_hinfo);

	if (tcp_hinfo.flags & RETRANSMIT) {
		/* clear FIN */
		if (cinfo->tcp->fin && !(TCP_CMP_INFO(other_cinfo)->flags & FIN))
			update_tcp_fin(cinfo->tcp, cinfo->skb, true);

		/* Retransmitted packet may conatin WIN_UPDATE or ACK_UPDATE */
		if (tcp_hinfo.flags & ACK_UPDATE ||
		    tcp_hinfo.flags & WIN_UPDATE)
			/* TODO: How to avoid retransmiting twice? */
			goto send_packet;

		update_tcp_compare_info(TCP_CMP_INFO(cinfo), &tcp_hinfo,
					cinfo->skb);
		if (ret & BYPASS_MASTER)
			ret |= UPDATE_MASTER_PACKET;
		return ret;
	}

	if ((tcp_hinfo.flags & HAVE_PAYLOAD) &&
	    (TCP_CMP_INFO(other_cinfo)->flags & FIN)) {
		statis.fin++;
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	if (tcp_hinfo.flags & (HAVE_PAYLOAD | SYN))
		/*
		 * This packet is not a retransmitted packet,
		 * and has data or SYN.
		 */
		return 0;

	if ((tcp_hinfo.flags & FIN) &&
	    (TCP_CMP_INFO(other_cinfo)->flags & FIN))
		goto send_packet;

	if (tcp_hinfo.flags & OLD_ACK)
		/* It is a packet with old ack seq */
		return ret;

	if (!(tcp_hinfo.flags & (WIN_UPDATE | ACK_UPDATE | DUP_ACK)))
		return 0;

send_packet:
	if (s_cinfo->skb) {
		new_skb = create_new_skb(skb, m_cinfo);
		if (!new_skb)
			return 0;
	} else
		new_skb = skb;
	update_tcp_compare_info(TCP_CMP_INFO(cinfo), &tcp_hinfo,
				cinfo->skb);

	ret = cinfo == m_cinfo ? BYPASS_MASTER : SAME_PACKET | CLONED_PACKET;
	return ret | UPDATE_MASTER_PACKET;
}

static void tcp_update_info(void *info, void *data, uint32_t length, struct sk_buff *skb)
{
	struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_cinfo = info;
	struct tcp_hdr_info tcp_hinfo;

	get_tcp_hdr_info(tcp, length, tcp_cinfo, &tcp_hinfo);

	if (unlikely(tcp_hinfo.flags & ERR_SKB))
		return;

	update_tcp_compare_info(tcp_cinfo, &tcp_hinfo, skb);
	update_tcp_sent_info(tcp_cinfo, tcp);
}

static void tcp_flush_packet(void *info)
{
	struct tcp_compare_info *tcp_cinfo = info;

	/* TODO: auto generate a new skb to update ack/window_size */

	if (tcp_cinfo->rcv_nxt != tcp_cinfo->sent_rcv_nxt)
		pr_warn("OOPS, rcv_nxt: 0x%x, sent_rcv_nxt: 0x%x\n",
			tcp_cinfo->rcv_nxt, tcp_cinfo->sent_rcv_nxt);

	if (tcp_cinfo->window != tcp_cinfo->sent_window)
		pr_warn("window: 0x%x, sent_window: 0x%x\n",
			tcp_cinfo->window, tcp_cinfo->sent_window);
}

static ipv4_compare_ops_t tcp_ops = {
	.compare = tcp_compare_packet,
	.compare_one_packet = tcp_compare_one_packet,
	.compare_fragment = tcp_compare_fragment,
	.update_info = tcp_update_info,
	.update_packet = tcp_update_packet,
	.flush_packets = tcp_flush_packet,
	.debug_print = debug_print_tcp,
};

static int statistics_status_show(struct seq_file *m, void *data)
{
	struct tcp_statistics *statis = m->private;

	OUTPUT_STATIS(m_error_packet);
	OUTPUT_STATIS(s_error_packet);
	OUTPUT_STATIS(sack);
	OUTPUT_STATIS(timestamp);
	OUTPUT_STATIS(other_options);
	OUTPUT_STATIS(psh);
	OUTPUT_STATIS(fin);
	OUTPUT_STATIS(other_flags);
	OUTPUT_STATIS(seq);
	OUTPUT_STATIS(window);
	OUTPUT_STATIS(ack_seq);
	OUTPUT_STATIS(doff);
	OUTPUT_STATIS(data_len);
	OUTPUT_STATIS(data);
	return 0;
}

static int statistics_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, statistics_status_show, inode->i_private);
}

static const struct file_operations statistics_status_ops = {
	.open		= statistics_status_open,
	.read		= seq_read,
	.llseek		= generic_file_llseek,
	.release	= single_release,
};

static void remove_statis_file(void)
{
#define REMOVE_STATIS_FILE(entry)	REMOVE_STATIS_FILE_L(statis_entry, entry)

	REMOVE_STATIS_FILE(status_entry);
	REMOVE_STATIS_FILE(m_error_packet_entry);
	REMOVE_STATIS_FILE(s_error_packet_entry);
	REMOVE_STATIS_FILE(other_options_entry);
	REMOVE_STATIS_FILE(sack_entry);
	REMOVE_STATIS_FILE(timestamp_entry);
	REMOVE_STATIS_FILE(seq_entry);
	REMOVE_STATIS_FILE(other_flags_entry);
	REMOVE_STATIS_FILE(psh_entry);
	REMOVE_STATIS_FILE(fin_entry);
	REMOVE_STATIS_FILE(window_entry);
	REMOVE_STATIS_FILE(ack_seq_entry);
	REMOVE_STATIS_FILE(doff_entry);
	REMOVE_STATIS_FILE(data_entry);
	REMOVE_STATIS_FILE(data_len_entry);
	REMOVE_STATIS_FILE(root_entry);
}

static int create_statis_file(void)
{
	int ret;

	statis_entry.root_entry = colo_create_dir("tcp", NULL);
	CHECK_RETURN_VALUE(statis_entry.root_entry);

	statis_entry.status_entry = colo_create_file("statistics_status",
						     &statistics_status_ops,
						     statis_entry.root_entry,
						     &statis);
	CHECK_RETURN_VALUE(statis_entry.status_entry);

#define CREATE_STATIS_FILE(elem)	CREATE_STATIS_FILE_L(statis_entry.root_entry, statis, elem)
	CREATE_STATIS_FILE(m_error_packet);
	CREATE_STATIS_FILE(s_error_packet);
	CREATE_STATIS_FILE(other_options);
	CREATE_STATIS_FILE(sack);
	CREATE_STATIS_FILE(timestamp);
	CREATE_STATIS_FILE(seq);
	CREATE_STATIS_FILE(other_flags);
	CREATE_STATIS_FILE(psh);
	CREATE_STATIS_FILE(fin);
	CREATE_STATIS_FILE(window);
	CREATE_STATIS_FILE(ack_seq);
	CREATE_STATIS_FILE(doff);
	CREATE_STATIS_FILE(data);
	CREATE_STATIS_FILE(data_len);

	return 0;

err:
	remove_statis_file();
	return ret;
}

static int __init compare_tcp_init(void)
{
	int ret;

	ret = register_ipv4_compare_ops(&tcp_ops, IPPROTO_TCP);
	if (ret)
		return ret;

	return create_statis_file();
}

static void __exit compare_tcp_fini(void)
{
	remove_statis_file();
	unregister_ipv4_compare_ops(&tcp_ops, IPPROTO_TCP);
}

module_init(compare_tcp_init);
module_exit(compare_tcp_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
