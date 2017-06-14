/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP module.
 *
 * Version:	@(#)ip_mpip.h	1.0.0	02/12/2013
 *
 * Authors:	Guibin Tian, <gbtian@gmail.com>
 *
 * Changes:
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _IP_MPIP_H
#define _IP_MPIP_H


#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>

#include <net/inet_sock.h>
#include <net/snmp.h>
#include <net/flow.h>

//The length of the CM block
//This value should better be calculated
#define MPIP_CM_LEN 25
//Node ID length, now it is 2. When changing this value, the length of CM also needs to be changed.
#define MPIP_CM_NODE_ID_LEN 2

//minimum/maximum buffer size of the out of order buffer
#define MPIP_TCP_BUF_MIN_LEN 200
#define MPIP_TCP_BUF_MAX_LEN 200

//different flags

//normal packet
#define MPIP_NORMAL_FLAGS 0
//ip address notification
#define MPIP_NOTIFY_FLAGS 1
//heartbeat packet
#define MPIP_HB_FLAGS 2
//mpip query packet
#define MPIP_ENABLE_FLAGS 3
//mpip confirmation packet
#define MPIP_ENABLED_FLAGS 4
//handshake packet
#define MPIP_SYNC_FLAGS 5
//maximum number of flags. Needs to be updated when adding flags.
#define MPIP_MAX_FLAGS 5

//priority value, for customization routing
#define MPIP_DELAY_PRIORITY 0
#define MPIP_QUEUING_DELAY_PRIORITY 1

//#define MPIP_FLAG_

//the sysctls. Explained in ip_mpip.c
extern int sysctl_mpip_enabled;
extern int sysctl_mpip_send;
extern int sysctl_mpip_rcv;
extern int sysctl_mpip_log;
extern int sysctl_mpip_tp_time;
extern int sysctl_mpip_bw_time;
extern int sysctl_mpip_exp_time;
extern int sysctl_mpip_bw_step;
extern int sysctl_mpip_path_diff;
extern int sysctl_mpip_qd;
extern int sysctl_mpip_skype;
extern int sysctl_mpip_hb;
extern int sysctl_mpip_use_tcp;
extern int sysctl_mpip_tcp_buf_count;

//deprecated variables
extern int max_pkt_len;
extern int global_stat_1;
extern int global_stat_2;
extern int global_stat_3;

//
//extern struct list_head wi_head;
//extern struct list_head pi_head;
//extern struct list_head ss_head;
//extern struct list_head la_head;
//extern struct list_head ps_head;

//The struct of the CM block
struct mpip_cm
{
	unsigned char	len;
	unsigned char	node_id[2];
	unsigned char	session_id;
	unsigned char	path_id;
	unsigned char	path_stat_id;
	u32				timestamp;
	__s32			delay;
	__be32          addr1;
	__be32          addr2;
	unsigned char	flags;
	__s16			checksum;
};

//Log table
struct mpip_log_table
{
	unsigned long				logjiffies;
	int					delay;
	int					min_delay;
	int 					queuing_delay;
	unsigned long				tp;
	struct list_head 			list;
};

//mpip query table. This table is for TCP only.
//Everytime we receive a mpip query, buffer it and piggyback
//with next TCP packet
struct mpip_query_table
{
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/
	struct list_head 	list;
};

//mpip enable table, Table 2 in the paper
struct mpip_enabled_table
{
	__be32				addr; /* receiver' ip seen by sender */
	__be16				port;
	bool				mpip_enabled;
	int 				sent_count;
	struct list_head 	list;
};

//IP address change notification table
struct addr_notified_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /*receiver's node id. */
	bool				notified;
	int					count;
	struct list_head 	list;
};

//working IP table. Mapping between node id and ip:port
struct working_ip_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /*receiver's node id. */
	__be32				addr; /* receiver' ip seen by sender */
	__be16				port;
	unsigned int 		protocol;
	unsigned char		session_id;
	struct list_head 	list;
};

//customized routing table
struct route_rule_table
{
	char *				dest_addr; /* receiver' ip seen by sender */
	char *				dest_port;
	int 				protocol;
	int					startlen;
	int					endlen;
	int					priority; /* 0: delay; 1: queuing delay; -1: invalid */
	struct list_head 	list;
};

//path table
struct path_info_table
{
	/*when sending pkts, check the bw to choose the fastest one*/
	/*update sent*/
	unsigned char 		node_id[MPIP_CM_NODE_ID_LEN]; /*destination node id*/
	unsigned char		path_id; /* path id: 0,1,2,3,4....*/
	unsigned char		session_id;
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/
//	unsigned int 		protocol;
	int 				min_delay;
	int     			ave_min_delay;
	int					max_delay;
	int     			delay;
	int     			ave_delay;
	int     			queuing_delay;
	int     			ave_queuing_delay;
	int     			max_queuing_delay;
	int					tmp;
	__u64				bw;  /* bandwidth */
	unsigned long 		fbjiffies; /* last feedback time of this path */
	unsigned char		count;
	__u64				pktcount;
	unsigned char		status;/* For tcp additional path:
	 	 	 	 	 	 	 	0: ready for use
	 	 	 	 	 	 	 	1: syn sent
	 	 	 	 	 	 	 	2: synack sent
	 	 	 	 	 	 	 	3: ack sent*/

	unsigned long		tpstartjiffies;
	unsigned long		tptotalbytes;
	unsigned long		tp;
	int					logcount;
	struct list_head	mpip_log;

	struct list_head 	list;
};

//out of order buffer
struct tcp_skb_buf
{
	__u32				seq;
	struct sk_buff *	skb;
//	unsigned long 		fbjiffies;
//	struct list_head 	list;
};

//this is stored in the session table. To store all the paths that belong to one session.
//should be deprecated, replace by path_bw_info
struct sort_path
{
	struct path_info_table *path_info;
	struct list_head 	list;
};

//path bandwidth. 
//this is stored in the session table. To store all the paths that belong to one session.
struct path_bw_info
{
	unsigned char		path_id; /* path id: 0,1,2,3,4....*/
	__u64				bw;  /* bandwidth */
	struct list_head 	list;
};

//session table. 
struct socket_session_table
{
	unsigned char		src_node_id[MPIP_CM_NODE_ID_LEN]; /* local node id*/
	unsigned char		dst_node_id[MPIP_CM_NODE_ID_LEN]; /* remote node id*/
	unsigned char   	session_id; /* sender's session id*/

//	struct list_head 	tcp_buf;
	struct tcp_skb_buf  tcp_buf[MPIP_TCP_BUF_MAX_LEN];
	__u32				next_seq;
	int 				buf_count;
	int 				max_buf_count;
	unsigned int 		protocol;

	/* socket information seen at the receiver side*/
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/

	unsigned long		tpinitjiffies;
	unsigned long		tpstartjiffies;
	unsigned long		tpbwjiffies;
	unsigned long		tptotalbytes;
	unsigned long		tprealtime;
	unsigned long		tphighest;
	struct list_head 	path_bw_list; //path bw of highest tp

	bool 				done;

	struct list_head 	list;
};

//path feedback table
struct path_stat_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /* sender's node id*/
	unsigned char 		session_id;
	unsigned char		path_id; /* path id: 0,1,2,3,4....*/
	__s32     			delay;
	bool				feedbacked;
	__u64				pktcount;
	unsigned long 		fbjiffies; /* last feedback time of this path's stat */
	struct list_head 	list;
};

//local ip list
struct local_addr_table
{
	__be32				addr;
	struct list_head 	list;
};


int mpip_init(void);

void mpip_log(const char *fmt, ...);

void print_node_id(unsigned char *node_id);

void print_addr(__be32 addr);

void print_addr_1(__be32 addr);

__be32 convert_addr(char a1, char a2, char a3, char a4);

char *in_ntoa(unsigned long in);

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2);

int		mpip_rcv(struct sk_buff *skb);

int		mpip_xmit(struct sk_buff *skb);

struct net_device *find_dev_by_addr(__be32 addr);

void print_mpip_cm(struct mpip_cm *cm);

void print_mpip_cm_1(struct mpip_cm *cm, int id);

bool ip_route_out( struct sk_buff *skb, __be32 saddr, __be32 daddr);

bool send_mpip_msg(struct sk_buff *skb, bool sender, bool reverse,
		unsigned char flags, unsigned char session_id);

bool check_path_info_status(struct sk_buff *skb,
		unsigned char *node_id, unsigned char session_id);

bool send_mpip_syn(struct sk_buff *skb_in, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	bool syn, bool ack,
		unsigned char session_id);

bool send_mpip_skb(struct sk_buff *skb_in, unsigned char flags);

bool get_skb_port(struct sk_buff *skb, __be16 *sport, __be16 *dport);

bool is_ack_pkt(struct sk_buff *skb);

bool is_pure_ack_pkt(struct sk_buff *skb);

bool send_pure_ack(struct sk_buff *skb);

bool insert_mpip_cm(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
					__be32 *new_saddr, __be32 *new_daddr,
					unsigned int protocol, unsigned char flags,
					unsigned char session_id);

bool insert_mpip_cm_1(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
					__be32 *new_saddr, __be32 *new_daddr,
					unsigned int protocol, unsigned char flags,
					unsigned char session_id);

int process_mpip_cm(struct sk_buff *skb);

bool check_bad_addr(__be32 addr);

void send_mpip_hb(struct sk_buff *skb, unsigned char session_id);

void send_mpip_enable(struct sk_buff *skb, bool sender, bool reverse);

void send_mpip_enabled(struct sk_buff *skb, bool sender, bool reverse);

int add_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

int delete_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

struct mpip_query_table *find_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

struct mpip_enabled_table *find_mpip_enabled(__be32 addr, __be16 port);

int add_mpip_enabled(__be32 addr, __be16 port, bool enabled);

bool is_mpip_enabled(__be32 addr, __be16 port);

bool is_local_addr(__be32 addr);

__be32 get_local_addr1(void);

__be32 get_local_addr2(void);

bool get_addr_notified(unsigned char *node_id);

struct addr_notified_table *find_addr_notified(unsigned char *node_id);

int add_addr_notified(unsigned char *node_id);

void process_addr_notified_event(unsigned char *node_id, unsigned char flags, __be32 addr1, __be32 addr2);

int add_working_ip(unsigned char *node_id, __be32 addr, __be16 port,
		unsigned char session_id, unsigned int protocol);

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr,
		__be16 port, unsigned int protocol);

unsigned char * find_node_id_in_working_ip(__be32 addr, __be16 port,
		unsigned int protocol);

struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char session_id, unsigned char path_id);

int add_path_stat(unsigned char *node_id, unsigned char session_id, unsigned char path_id);

int update_path_stat_delay(unsigned char *node_id, unsigned char session_id, unsigned char path_id, u32 timestamp);

int update_path_delay(unsigned char path_id, __s32 delay);

bool ready_path_info(int id, unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id);

int update_path_info(unsigned char session_id);


struct socket_session_table *get_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id,
		 	 	 	 	unsigned char path_id,
		 	 	 	 	unsigned int protocol);

int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport);

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport, unsigned char session_id);

bool is_dest_added(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol);

bool init_mpip_tcp_connection(struct sk_buff *skb,
							__be32 daddr1, __be32 daddr2,
							__be32 saddr, __be32 daddr,
							__be16 sport, __be16 dport,
							unsigned char session_id);

int add_origin_path_info_tcp(unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);


int add_path_info_tcp(int id, unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);

int add_path_info_udp(unsigned char *node_id, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);

bool is_original_path(unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id);

unsigned char find_fastest_path_id(unsigned char *node_id,
			   __be32 *saddr, __be32 *daddr,  __be16 *sport, __be16 *dport,
			   __be32 origin_saddr, __be32 origin_daddr, __be16 origin_sport,
			   __be16 origin_dport, unsigned char session_id,
			   unsigned int protocol, unsigned int len, bool is_short);

unsigned char find_earliest_path_stat_id(unsigned char *dest_node_id, unsigned char session_id, __s32 *delay);

// unsigned char get_path_stat_id(unsigned char *dest_node_id, unsigned char session_id, __s32 *delay)

struct socket_session_table *get_sender_session(__be32 saddr, __be16 sport,
							 __be32 daddr, __be16 dport, unsigned int protocol);

void add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport,
					   unsigned int protocol);

struct socket_session_table *find_socket_session(unsigned char session_id);

void add_session_totalbytes(unsigned char session_id, unsigned int len);

void update_session_tp(unsigned char session_id, unsigned int len);

__be32 find_local_addr(__be32 addr);

void get_available_local_addr(void);

void update_addr_change(unsigned long event);

int add_to_tcp_skb_buf(struct sk_buff *skb, unsigned char session_id);

//unsigned char get_session(struct sk_buff *skb);

void add_route_rule(const char *dest_addr, const char *dest_port,
					int protocol, int startlen,
					int endlen, int priority);

int get_pkt_priority(__be32 dest_addr, __be16 dest_port,
					unsigned int protocol, unsigned int len);

void reset_mpip(void);

unsigned char get_tcp_session(struct sk_buff *skb);

#endif	/* _IP_MPIP_H */
