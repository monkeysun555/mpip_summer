#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/ip_mpip.h>


//When generating a new session id, this value will be used. Make it static to be gloablly unique
static unsigned char static_session_id = 1;
//When generating a new path id, this value will be used. Make it static to be gloablly unique
static unsigned char static_path_id = 1;
//The feedback time for each path. jiffies is the clock tick from system start.
static unsigned long earliest_fbjiffies = 0;

//mpip query table, TCP only, when receiving a mpip query, it buffers the query, and piggyback the reply 
//in next TCP packet. Because TCP has the NAT issue.
static LIST_HEAD(mq_head);
//mpip query table, for handshake, Table 2 in the paper
static LIST_HEAD(me_head);
//When local ip address changes, the is used to track the notification to the other ends of connections
static LIST_HEAD(an_head);
//working ip address of each node. each node id can have multiple ip address
static LIST_HEAD(wi_head);
//path information table, Table 5 in the paper
static LIST_HEAD(pi_head);
//session table, Table 4 in the paper
static LIST_HEAD(ss_head);
//local IP address table
static LIST_HEAD(la_head);
//path statistics table, Table 6 in the paper
static LIST_HEAD(ps_head);
//customized routing table, Table 7 in the paper
static LIST_HEAD(rr_head);

//debug only
int global_stat_1;
//debug only
int global_stat_2;
//debug only
int global_stat_3;
//debug only
static unsigned char s_s_id = 0;
//debug only
static unsigned char s_p_id = 0;

//Judge whether two node ids are the same. byte by byte comparison
bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2)
{
	int i;

	if (!node_id_1 || !node_id_2)
		return false;

	for(i = 0; i < MPIP_CM_NODE_ID_LEN; i++)
	{
		if (node_id_1[i] != node_id_2[i])
			return false;
	}

	return true;
}

//Print user friendly node id.
void print_node_id(unsigned char *node_id)
{
	if (!node_id)
		return;
	mpip_log( "%02x-%02x\n", node_id[0], node_id[1]);
}

//Judge whether the IP address is local one, 192.168.*.*
//used in debug
bool is_lan_addr(__be32 addr)
{
	char *p = (char *) &addr;

	if ((p[0] & 255) == 192 &&
		(p[1] & 255) == 168)
	{
		return true;
	}
	return false;
}

//Print IP address in user friendly format
void print_addr(__be32 addr)
{
	char *p = (char *) &addr;
	mpip_log( "%d.%d.%d.%d\n",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

}

//Print IP address in user friendly format. The same for now. Had different implementation during debug
void print_addr_1(__be32 addr)
{
	char *p = (char *) &addr;
	printk( "%d.%d.%d.%d\n",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

}

//convert string IP to __be32 format
__be32 convert_addr(char a1, char a2, char a3, char a4)
{
	__be32 addr;
	char *p = (char *) &addr;
	p[0] = a1;
	p[1] = a2;
	p[2] = a3;
	p[3] = a4;

	return (__be32)addr;
}

//convert IP address to string format
char *in_ntoa(unsigned long in)
{
	char *buff = kzalloc(18, GFP_ATOMIC);
	char *p;

	p = (char *) &in;
	sprintf(buff, "%d.%d.%d.%d",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	return(buff);
}

//find a mpip_query_table item in the table of mq_head
struct mpip_query_table *find_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;

	list_for_each_entry(mpip_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			return mpip_query;
		}
	}

	return NULL;
}
//remove mpip_query_table item from mq_head
int delete_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;
	struct mpip_query_table *tmp_query;
	list_for_each_entry_safe(mpip_query, tmp_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(mpip_query->list));
			kfree(mpip_query);

			return 1;
		}
	}

	return 0;
}

//add one mpip_query_table item into mq_head
int add_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *item = find_mpip_query(saddr, daddr, sport, dport);

	if (item)
	{
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_query_table),	GFP_ATOMIC);
	item->saddr = saddr;
	item->daddr = daddr;
	item->sport = sport;
	item->dport = dport;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &mq_head);

	mpip_log( "mq: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
	print_addr(saddr);
	print_addr(saddr);

	return 1;
}

//find mpip_enable_table item from me_head
struct mpip_enabled_table *find_mpip_enabled(__be32 addr, __be16 port)
{
	struct mpip_enabled_table *mpip_enabled;

	list_for_each_entry(mpip_enabled, &me_head, list)
	{
		if ((addr == mpip_enabled->addr) && (port == mpip_enabled->port))
		{
			return mpip_enabled;
		}
	}

	return NULL;
}

//add mpip_enabled_table item into table me_head
int add_mpip_enabled(__be32 addr, __be16 port, bool enabled)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct mpip_enabled_table *item = find_mpip_enabled(addr, port);

	if (item)
	{
		item->mpip_enabled = enabled;
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_enabled_table),	GFP_ATOMIC);
	item->addr = addr;
	item->port = port;
	item->mpip_enabled = enabled;
	item->sent_count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &me_head);

	mpip_log("%d, %d, %s, %s, %d\n", port, enabled, __FILE__, __FUNCTION__, __LINE__);
	print_addr(addr);

	return 1;
}

//check whether a ip:port is mpip enabled.
bool is_mpip_enabled(__be32 addr, __be16 port)
{
	bool enabled = false;
	struct mpip_enabled_table *item = NULL;

	if (!sysctl_mpip_enabled)
		enabled = false;

	item = find_mpip_enabled(addr, port);

	if (!item)
		enabled = false;
	else
		enabled = item->mpip_enabled;

	return enabled;
}

//add customized routing entry into rr_head
void add_route_rule(const char *dest_addr, const char *dest_port,
					int protocol, int startlen,
					int endlen, int priority)
{
	struct route_rule_table *item = NULL;

	if (!dest_addr || !dest_port)
		return;

	item = kzalloc(sizeof(struct route_rule_table),	GFP_ATOMIC);

	item->dest_addr = kzalloc(strlen(dest_addr), GFP_ATOMIC);
	memcpy(item->dest_addr, dest_addr, strlen(dest_addr));
	item->dest_port = kzalloc(strlen(dest_port), GFP_ATOMIC);
	memcpy(item->dest_port, dest_port, strlen(dest_port));
	item->protocol = protocol;
	item->startlen = startlen;
	item->endlen = endlen;
	item->priority = priority;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &rr_head);
}

//From table rr_head, given all these inputs, return whether this packet is 
//throughput piroity or responsiveness priority
int get_pkt_priority(__be32 dest_addr, __be16 dest_port,
					unsigned int protocol, unsigned int len)
{
	struct route_rule_table *route_rule;

	char* p = NULL;
	char* str_dest_addr = kzalloc(12, GFP_ATOMIC);
	char* str_dest_port = kzalloc(12, GFP_ATOMIC);

	p = (char *) &dest_addr;
	sprintf(str_dest_addr, "%03d.%03d.%03d.%03d",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	__be16 port = htons((unsigned short int) dest_port);

	sprintf(str_dest_port, "%d", port);

//	printk("%s, %s, %d, %d, %d, %s, %d\n",
//			str_dest_addr, str_dest_port, dest_port, protocol, len,
//			 __FILE__, __LINE__);

	list_for_each_entry(route_rule, &rr_head, list)
	{
		if ((strcmp(route_rule->dest_addr, "-1") == 0 || strcmp(str_dest_addr, route_rule->dest_addr) == 0) &&
			(strcmp(route_rule->dest_port, "-1") == 0 || strcmp(str_dest_port, route_rule->dest_port) == 0) &&
			(route_rule->protocol == -1 || protocol == route_rule->protocol) &&
			(route_rule->startlen == -1 || len >= route_rule->startlen) &&
			(route_rule->endlen == -1 || len <= route_rule->endlen))
		{
//			printk("%s, %s, %d, %d, %d, %s, %d\n",
//					str_dest_addr, str_dest_port, protocol, len,
//					route_rule->priority, __FILE__, __LINE__);

			return route_rule->priority;
		}
	}
	return -1;
}

//get the first local ip address from la_head
__be32 get_local_addr1(void)
{
	struct local_addr_table *local_addr;

	int index = 0;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (index == 0)
			return local_addr->addr;
	}

	return 0;
}

//get the second local ip address from la_head
__be32 get_local_addr2(void)
{
	struct local_addr_table *local_addr;

	int index = 0;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (index == 1)
			return local_addr->addr;

		++index;
	}

	return 0;
}

//judge whether one ip address is local ip address
bool is_local_addr(__be32 addr)
{
	if (find_local_addr(addr) > 0)
		return true;

	return false;
}

//add on ip:port into wi_head for one node
int add_working_ip(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct working_ip_table *item = NULL;


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	item = find_working_ip(node_id, addr, port, protocol);
	if (item)
	{
		item->session_id = session_id;
		return 0;
	}

	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->addr = addr;
	item->port = port;
	item->session_id = session_id;
	item->protocol = protocol;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &wi_head);

//	mpip_log( "wi:");
//
//	print_node_id(__FUNCTION__, node_id);
//	print_addr(__FUNCTION__, addr);

	return 1;
}

//find one working_ip_table entry from wi_head
struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr,
		__be16 port, unsigned int protocol)
{
	struct working_ip_table *working_ip;

	if (!node_id)
		return NULL;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if (is_equal_node_id(node_id, working_ip->node_id) &&
				(addr == working_ip->addr) &&
				(port == working_ip->port)
				&&(protocol == working_ip->protocol)
				)
		{
			return working_ip;
		}
	}

	return NULL;
}

//given the protocol and ip:port, return the node id from wi_head
unsigned char * find_node_id_in_working_ip(__be32 addr, __be16 port,
											unsigned int protocol)
{
	struct working_ip_table *working_ip;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if ((addr == working_ip->addr) && (port == working_ip->port) &&
			(protocol == working_ip->protocol))
		{
			return working_ip->node_id;
		}
	}

	return NULL;
}

//find a addr_notified_table item from an_head. This is for dynamic IP change
struct addr_notified_table *find_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *addr_notified;

	if (!node_id)
		return NULL;

	list_for_each_entry(addr_notified, &an_head, list)
	{
		if (is_equal_node_id(node_id, addr_notified->node_id))
		{
			return addr_notified;
		}
	}

	return NULL;
}

//return whether whether one node has been notified about the ip address change
bool get_addr_notified(unsigned char *node_id)
{
	bool notified = true;
	struct addr_notified_table *addr_notified = find_addr_notified(node_id);
	if (addr_notified)
	{
		notified = addr_notified->notified;
		if (!notified)
		{
			addr_notified->count += 1;
			if (addr_notified->count > 5)
			{
				addr_notified->notified = true;
				addr_notified->count = 0;
			}
		}
		else
			addr_notified->count = 0;

		mpip_log("%d, %s, %d\n", notified, __FILE__, __LINE__);
		return notified;
	}

	return true;
}

//add a add_notified_table item into an_head
int add_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *item = NULL;


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_addr_notified(node_id))
		return 0;


	item = kzalloc(sizeof(struct addr_notified_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->notified = true;
	item->count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &an_head);

//	mpip_log( "an:");
//
//	print_node_id(__FUNCTION__, node_id);

	return 1;
}

//when receiving a address notified event, the receiver will clear up all 
//relative tables, and reset the whole mpip
void process_addr_notified_event(unsigned char *node_id, unsigned char flags, __be32 addr1, __be32 addr2)
{

//	reset_mpip();
//	return;

	struct working_ip_table *working_ip;
	struct working_ip_table *tmp_ip;

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	if (!node_id || flags != 1)
		return;

	if (node_id[0] == node_id[1])
	{
		return;
	}

	mpip_log("%s, %d\n", __FILE__, __LINE__);
	print_addr(addr1);
	print_addr(addr2);


	// list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
	// {
	// 	if (is_equal_node_id(node_id, working_ip->node_id))
	// 	{
	// 		mpip_log("%s, %d\n", __FILE__, __LINE__);
	// 		if(working_ip->addr != addr1 && working_ip->addr != addr2){
	// 			print_addr(working_ip->addr);
	// 			list_del(&(working_ip->list));
	// 			kfree(working_ip);
	// 		}
	// 	}
	// }

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		if (is_equal_node_id(node_id, path_info->node_id))
		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
			if(path_info->daddr != addr1 && path_info->daddr != addr2){
				list_del(&(path_info->list));
				kfree(path_info);
				// path_info->status = 4;
				// path_info->bw = 0;
				list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
				{
					if (is_equal_node_id(node_id, path_stat->node_id))
					{
						if(path_stat->path_id == path_info->path_id){
							list_del(&(path_stat->list));
							kfree(path_stat);
						}
					}
				}
			}
		}
	}	
	
}

//when receiving a packet, update the one way delay information of the incoming path
int update_path_stat_delay(unsigned char *node_id, unsigned char session_id, unsigned char path_id, u32 timestamp)
{
/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
    struct timespec tv;
	u32  midtime;

	if (!node_id || (path_id == 0) || session_id == 0 )
		return 0;

	if (node_id[0] == node_id[1])
		return 0;

	path_stat = find_path_stat(node_id, session_id, path_id);
	if (path_stat)
	{
		getnstimeofday(&tv);
		midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 1000  + (tv.tv_nsec * 1000) / NSEC_PER_MSEC;
//		midtime = jiffies;
		path_stat->delay = midtime - timestamp;
		path_stat->feedbacked = false;
		path_stat->pktcount += 1;
	}


	return 1;
}

//when receiving a feedback, update the delay value in the path info table.
int update_path_delay(unsigned char path_id, __s32 delay)
{
    struct path_info_table *path_info;
	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->path_id == path_id)
		{
//			if (path_info->delay < delay)
//			{
//				if (path_info->bw <= sysctl_mpip_bw_step)
//					path_info->bw = 1;
//				else
//					path_info->bw -= sysctl_mpip_bw_step;
//			}
//			else if (path_info->delay > delay)
//			{
//				path_info->bw += sysctl_mpip_bw_step;
//
//				if (path_info->bw >= 1000)
//					path_info->bw = 1000;
//			}


			if (path_info->count == 0)
			{
				path_info->delay = delay;
			}
			else
			{
				path_info->delay = (99 * path_info->delay + delay) / 100;
//				path_info->delay = delay;
			}

			if (path_info->min_delay > delay || path_info->min_delay == -1)
			{
//				path_info->min_delay = (99 * path_info->min_delay + delay) / 100;;
				path_info->min_delay = delay;
			}

			if (path_info->max_delay < delay || path_info->max_delay == -1)
			{
				//path_info->max_delay = (99 * path_info->max_delay + delay) / 100;;
				path_info->max_delay = delay;
			}

			path_info->queuing_delay = path_info->delay - path_info->min_delay;
			if (path_info->queuing_delay > path_info->max_queuing_delay || path_info->max_queuing_delay == -1)
			{
				path_info->max_queuing_delay = path_info->queuing_delay;
			}

			//update_path_info(path_info->session_id);

			break;
		}
	}


	return 1;
}



//__s32 calc_si_diff(bool is_delay)
//{
//	__s32 si = 0;
//	__s32 K = 0;
//	__s32 sigma = 0;
//	__s32 diff = 0;
//	__s32 max = 0;
//	struct path_info_table *path_info, *prev_info;
//
//	if (is_delay)
//	{
//		list_for_each_entry(path_info, &pi_head, list)
//		{
//			prev_info = list_entry(path_info->list.prev, typeof(*path_info), list);
//			if (!prev_info)
//				continue;
//
//
//			diff = (path_info->ave_min_delay - prev_info->ave_min_delay > 0) ?
//				   (path_info->ave_min_delay - prev_info->ave_min_delay) :
//				   (prev_info->ave_min_delay - path_info->ave_min_delay);
//
//			sigma += diff;
//			++K;
//
////			max = (path_info->delay > prev_info->delay) ?
////				   path_info->delay : prev_info->delay;
////
////
////			if (max > diff)
////			{
////				if (max == -500)
////				{
////					max = -499;
////				}
////				sigma += (100 * diff) / (max + 500);
////				++K;
////			}
//		}
//	}
//	else
//	{
//		list_for_each_entry(path_info, &pi_head, list)
//		{
//			prev_info = list_entry(path_info->list.prev, typeof(*path_info), list);
//			if (!prev_info)
//				continue;
//
//
//			diff = (path_info->ave_max_delay - prev_info->ave_max_delay > 0) ?
//				   (path_info->ave_max_delay - prev_info->ave_max_delay) :
//				   (prev_info->ave_max_delay - path_info->ave_max_delay);
//
//			sigma += diff;
//			++K;
//
////			max = (path_info->queuing_delay > prev_info->queuing_delay) ?
////				   path_info->queuing_delay : prev_info->queuing_delay;
////
////			if (max > diff)
////			{
////				if (max == -500)
////				{
////					max = -499;
////				}
////				sigma += (100 * diff) / (max + 500);
////				++K;
////			}
//		}
//	}
//
//	if (K == 0)
//		si = 0;
//	else
//		si = sigma / K;
//
//	return si;
//}

//calculate the difference of two values. Make it a function because I tried to 
//add the smooth index into the calculation.
__s32 calc_diff(__s32 value, __s32 min_value, bool is_delay)
{
	__s32 diff = value - min_value;
//	__s32 si = calc_si_diff(is_delay);
//	return diff * si;
	return diff;
}

//When sorting different paths, checke whether one path has already been added into the sorted list.
//It is for packet assignment among paths. It is called in update_path_info wheneven receiving a packet.
bool is_in_sorted_list(struct list_head *sorted_list, struct path_info_table *path_info)
{
	if (!sorted_list)
		return false;

	struct sort_path *sp = NULL;

	list_for_each_entry(sp, sorted_list, list)
	{
		if (sp->path_info->path_id == path_info->path_id)
			return true;
	}
	return false;

}

//calculate the similarity of all paths that belong to the same session.
//This method is deprecated. Don't use it anymore. It was for packet assignment among paths.
int calc_path_similarity(unsigned char session_id)
{
	struct path_info_table *path_info = NULL;
	struct path_info_table *prev_info = NULL;
	__s32 si = 0;
	__s32 K = 0;
	__s32 sigma = 0;
	__s32 diff = 0;
	__s32 max = 0;

	if (session_id <= 0)
		return 0;

	//use the min_delay and delay value to calculate

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;

		if (!prev_info)
		{
			prev_info = path_info;
			continue;
		}


		diff = abs(path_info->min_delay - prev_info->min_delay) + abs(path_info->delay - prev_info->delay);

		sigma += diff;
		++K;

//		printk("%d, %d, %s, %d\n", sigma, K, __FILE__, __LINE__);

		prev_info = path_info;

	}

	if (K == 0)
		si = 0;
	else
		si = sigma / (2*K);

//	printk("%d, %d, %s, %d\n", sigma, K, __FILE__, __LINE__);

	return si;
}

//get the bandwidth of a path that belongs to a session id. bw is the default value 
//if the path is not in the table
__u64 get_path_bw(unsigned char path_id, unsigned char session_id, __u64 bw)
{
	struct path_bw_info *path_bw = NULL;

	if (session_id <= 0 || path_id <= 0)
	{
		return bw;
	}

	struct socket_session_table *socket_session = find_socket_session(session_id);

	if(!socket_session)
		return bw;

	list_for_each_entry(path_bw, &(socket_session->path_bw_list), list)
	{
		if (path_bw->path_id == path_id)
			return path_bw->bw;
	}

	return bw;
}

//everytime a node receives a packet, it updates the table of path info. This method is very important.
//it mainly updates the weight of each path.
int update_path_info(unsigned char session_id)
{
	struct path_info_table *path_info;
	int min_queuing_delay = -1;
	int min_delay = -1;
	int min_min_delay = -1;
	int max_queuing_delay = 0;
	int max_delay = 0;
	int max_min_delay = 0;

	__u64 totalbw = 0;
	__u64 totaltmp = 0;

	if (session_id <= 0)
		return 0;

	struct list_head sorted_list;
	INIT_LIST_HEAD(&(sorted_list));
	int count = 0;


	while(true)
	{
		struct path_info_table *min_path = NULL;
		__s32 min_value = -1;
		list_for_each_entry(path_info, &pi_head, list)
		{
			if (path_info->session_id != session_id)
				continue;

			if (!is_in_sorted_list(&sorted_list, path_info))
			{
				if (path_info->delay < min_value || min_value == -1)
				{
					min_value = path_info->delay;
					min_path = path_info;
				}
			}
		}

		if (min_path != NULL)
		{
			struct sort_path *item = kzalloc(sizeof(struct sort_path),	GFP_ATOMIC);
			if (!item)
				break;

			item->path_info = min_path;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(sorted_list));
			++count;
		}
		else
			break;
	}

	struct sort_path *sp = NULL;
	struct sort_path *next_sp = NULL;
	if (count == 4)
	{
		list_for_each_entry(sp, &sorted_list, list)
		{
			next_sp = list_entry(sp->list.next, typeof(*sp), list);
			if(next_sp)
			{
				sp->path_info->ave_delay = next_sp->path_info->ave_delay =
										(sp->path_info->delay + next_sp->path_info->delay) / 2;

//				printk("%d, %d: %d, %d, %d, %d\n", sp->path_info->path_id, next_sp->path_info->path_id,
//						sp->path_info->delay, next_sp->path_info->delay,
//						sp->path_info->ave_delay,
//						__LINE__);

				sp = next_sp;
			}
		}
	}
	else
	{
		list_for_each_entry(sp, &sorted_list, list)
		{
			sp->path_info->ave_delay = sp->path_info->delay;
		}
	}

	list_for_each_entry_safe(sp, next_sp, &sorted_list, list)
	{
		list_del(&(sp->list));
		kfree(sp);
	}


	struct list_head sorted_list_1;
	INIT_LIST_HEAD(&(sorted_list_1));
	int count_1 = 0;


	while(true)
	{
		struct path_info_table *min_path = NULL;
		__s32 min_value = -1;
		list_for_each_entry(path_info, &pi_head, list)
		{
			if (path_info->session_id != session_id)
				continue;

			if (!is_in_sorted_list(&sorted_list_1, path_info))
			{
				if (path_info->min_delay < min_value || min_value == -1)
				{
					min_value = path_info->min_delay;
					min_path = path_info;
				}
			}
		}

		if (min_path != NULL)
		{
			struct sort_path *item = kzalloc(sizeof(struct sort_path),	GFP_ATOMIC);
			if (!item)
				break;

			item->path_info = min_path;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(sorted_list_1));
			++count_1;
		}
		else
			break;
	}

	sp = NULL;
	next_sp = NULL;
	if (count_1 == 4)
	{
		list_for_each_entry(sp, &sorted_list_1, list)
		{
			next_sp = list_entry(sp->list.next, typeof(*sp), list);
			if(next_sp)
			{
				sp->path_info->ave_min_delay = next_sp->path_info->ave_min_delay =
						(sp->path_info->min_delay + next_sp->path_info->min_delay) / 2;

//				printk("%d, %d: %d, %d, %d, %d\n", sp->path_info->path_id, next_sp->path_info->path_id,
//						sp->path_info->min_delay, next_sp->path_info->min_delay,
//						sp->path_info->ave_min_delay,
//						__LINE__);
				sp = next_sp;
			}
		}
	}
	else
	{
		list_for_each_entry(sp, &sorted_list_1, list)
		{
			sp->path_info->ave_min_delay = sp->path_info->min_delay;
		}
	}

	list_for_each_entry_safe(sp, next_sp, &sorted_list_1, list)
	{
		list_del(&(sp->list));
		kfree(sp);
	}

	struct list_head sorted_list_2;
	INIT_LIST_HEAD(&(sorted_list_2));
	int count_2 = 0;


	while(true)
	{
		struct path_info_table *min_path = NULL;
		__s32 min_value = -1;
		list_for_each_entry(path_info, &pi_head, list)
		{
			if (path_info->session_id != session_id)
				continue;

			if (!is_in_sorted_list(&sorted_list_2, path_info))
			{
				if (path_info->queuing_delay < min_value || min_value == -1)
				{
					min_value = path_info->queuing_delay;
					min_path = path_info;
				}
			}
		}

		if (min_path != NULL)
		{
			struct sort_path *item = kzalloc(sizeof(struct sort_path),	GFP_ATOMIC);
			if (!item)
				break;

			item->path_info = min_path;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(sorted_list_2));
			++count_2;
		}
		else
			break;
	}

	sp = NULL;
	next_sp = NULL;
	if (count_2 == 4)
	{
		list_for_each_entry(sp, &sorted_list_2, list)
		{
			next_sp = list_entry(sp->list.next, typeof(*sp), list);
			if(next_sp)
			{
				sp->path_info->ave_queuing_delay = next_sp->path_info->ave_queuing_delay =
						(sp->path_info->queuing_delay + next_sp->path_info->queuing_delay) / 2;
//				printk("%d, %d: %d, %d, %d, %d\n", sp->path_info->path_id, next_sp->path_info->path_id,
//						sp->path_info->queuing_delay, next_sp->path_info->queuing_delay,
//						sp->path_info->ave_queuing_delay,
//						__LINE__);
				sp = next_sp;
			}
		}
	}
	else
	{
		list_for_each_entry(sp, &sorted_list_2, list)
		{
			sp->path_info->ave_queuing_delay = sp->path_info->queuing_delay;
		}
	}

	list_for_each_entry_safe(sp, next_sp, &sorted_list_2, list)
	{
		list_del(&(sp->list));
		kfree(sp);
	}


	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;

		if (path_info->ave_delay < min_delay || min_delay == -1)
		{
			min_delay = path_info->delay;
		}

		if (path_info->ave_delay > max_delay || max_delay == -1)
		{
			max_delay = path_info->delay;
		}

		if (path_info->ave_min_delay < min_min_delay || min_min_delay == -1)
		{
			min_min_delay = path_info->min_delay;
		}

		if (path_info->ave_min_delay > max_min_delay || max_min_delay == -1)
		{
			max_min_delay = path_info->min_delay;
		}

		if (path_info->ave_queuing_delay < min_queuing_delay || min_queuing_delay == -1)
		{
			min_queuing_delay = path_info->queuing_delay;
		}

		if (path_info->ave_queuing_delay > max_queuing_delay || max_queuing_delay == -1)
		{
			max_queuing_delay = path_info->queuing_delay;
		}
	}

	if (min_queuing_delay == -1)
	{
		return 0;
	}

	int min_tmp = -1;
	int path_count = 0;
	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;

//		int tmp = 0;
//		if (max_min_delay - min_min_delay > sysctl_mpip_path_diff)
//		{
//			tmp = max_delay - path_info->ave_delay;
//		}
//		else
//		{
//			tmp = max_queuing_delay - path_info->ave_queuing_delay;
//		}

		int tmp = max_queuing_delay - path_info->queuing_delay;

		if (sysctl_mpip_qd == 0)
			tmp = max_delay - path_info->delay;


		// __be32 ip1 = convert_addr(171, 21, 1, 2);
		// __be32 ip2 = convert_addr(172, 21, 2, 2);
		// __be32 ip3 = convert_addr(172, 21, 1, 3);
		// __be32 ip4 = convert_addr(172, 21, 2, 3);

		// if ((path_info->saddr == ip1) && (path_info->daddr == ip4) ||
		// 	(path_info->saddr == ip2) && (path_info->daddr == ip3))
		// {
		// 	tmp = 0;
		// }

		path_info->tmp = tmp;

		totaltmp += tmp;

		path_count++;
	}

	if (totaltmp == 0)
	{
		return 1;
	}

	// path_count = 2;
	int averatio = 1000 / path_count;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;
		// if (path_info->status == 4)
		// {
		// 	path_info->bw = 0;
		// 	continue;
		// }

		__u64 highbw = get_path_bw(path_info->path_id, session_id, path_info->bw);

		int ratio = (1000 * path_info->tmp) / totaltmp;
		if (ratio >= averatio)
		{
			path_info->bw += sysctl_mpip_bw_step;
			if (path_info->bw >= 1000)
				path_info->bw = 1000;
		}
		else
		{
			if (path_info->bw <= 100)
				path_info->bw = 100;
			else
				path_info->bw -= sysctl_mpip_bw_step;
		}
		// __be32 ip1 = convert_addr(192, 168, 255, 40);
		__be32 ip1 = convert_addr(172, 21, 3, 2);  //eth1 
		// __be32 ip1 = convert_addr(216, 165, 113, 122);  //eth0 
		__be32 ip2 = convert_addr(172, 21, 2, 2);  //eth1 inside
		__be32 ip3 = convert_addr(172, 21, 3, 3);  //eth1 inside
		// __be32 ip3 = convert_addr(216, 165, 113, 123);  //eth0 outside
		// __be32 ip3 = convert_addr(192, 168, 254, 200);
		__be32 ip4 = convert_addr(172, 21, 2, 3);  //eth1 outside
		__be32 ip5 = convert_addr(216, 165, 113, 223); //eth0 lenovo
		__be32 ip6 = convert_addr(172, 21, 2 , 20);

		if ((path_info->saddr == ip1) && (path_info->daddr == ip4) ||
			(path_info->saddr == ip2) && (path_info->daddr == ip3) ||
			(path_info->saddr == ip4) && (path_info->daddr == ip5) ||
			(path_info->saddr == ip3) && (path_info->daddr == ip6))
		{
			path_info->bw = 0;
		}
		// else if (path_info->saddr == ip1)
		// {
		// 	path_info->bw = 250;
		// }
		// else if (path_info->saddr == ip2)
		// {
		// 	path_info->bw = 500;
		// }
	}

	return 1;
}

//this is for the mpip handshake, if the path_info has a status value of 0, 
//means the path has been three way handshaked. otherwise, some handshake 
//packet will be sent out.
bool check_path_info_status(struct sk_buff *skb,
		unsigned char *node_id, unsigned char session_id)
{
	struct path_info_table *path_info;

	if (!node_id || (session_id <= 0))
		return false;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(node_id, path_info->node_id) &&
		    (session_id == path_info->session_id) &&
		    (path_info->status != 0))
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			send_mpip_syn(skb, path_info->saddr, convert_addr(192, 168, 1, 15),
					path_info->sport, path_info->dport,	true, false,
					session_id);

		}
	}

	return true;
}


//find path_stat_table from ps_head
struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char session_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	if (!node_id || (path_id == 0) || session_id == 0)
		return NULL;

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
			(path_stat->path_id == path_id) && 
			path_stat->session_id == session_id)
		{
			return path_stat;
		}
	}

	return NULL;
}

//add a path_stat_table into ps_head
int add_path_stat(unsigned char *node_id, unsigned char session_id, unsigned char path_id)
{
	struct path_stat_table *item = NULL;

	if (!node_id || (path_id == 0) || session_id == 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_path_stat(node_id, session_id, path_id))
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);


	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->path_id = path_id;
	item->session_id = session_id;
	item->delay = 0;
	item->feedbacked = false;
	item->fbjiffies = jiffies;
	item->pktcount = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ps_head);

	//mpip_log( "ps: %d", path_id);
	//print_node_id(node_id);

	return 1;
}


//get the session entry from ss_head when sending a packet.
struct socket_session_table *get_sender_session(__be32 saddr, __be16 sport,
						__be32 daddr, __be16 dport, unsigned int protocol)
{
	struct socket_session_table *socket_session;

//	printk("%s, %d\n", __FILE__, __LINE__);
//	print_addr(__FUNCTION__, saddr);
//	print_addr(__FUNCTION__, daddr);
//	printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);


	list_for_each_entry(socket_session, &ss_head, list)
	{
		if ((socket_session->saddr == saddr) &&
			(socket_session->sport == sport) &&
			(socket_session->daddr == daddr) &&
			(socket_session->dport == dport) &&
			(socket_session->protocol == protocol))
		{
//			printk("%s, %d\n", __FILE__, __LINE__);
//			print_addr(__FUNCTION__, saddr);
//			print_addr(__FUNCTION__, daddr);
//			printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

			return socket_session;
		}
	}

	return NULL;
}

//add session entry into ss_head. Here we generate the session_id from the static_session_id variable.
//and some other default value. This is called when sending a packet.
void add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport,
					   unsigned int protocol)
{
	struct socket_session_table *item = NULL;

	int i;
//	if (!is_lan_addr(saddr) || !is_lan_addr(daddr))
//	{
//		return 0;
//	}

	if (!src_node_id || !dst_node_id)
		return;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return;
	}

	if (get_sender_session(saddr, sport, daddr, dport, protocol))
		return;


	item = kzalloc(sizeof(struct socket_session_table),	GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

//	INIT_LIST_HEAD(&(item->tcp_buf));
	for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
	{
		item->tcp_buf[i].seq = 0;
		item->tcp_buf[i].skb = NULL;
	}

	item->next_seq = 0;
	item->buf_count = 0;
	item->max_buf_count = MPIP_TCP_BUF_MAX_LEN;
	item->protocol = protocol;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->tphighest = 0;
	item->tprealtime = 0;
	item->tpstartjiffies = jiffies;
	item->tpbwjiffies = jiffies;
	item->tpinitjiffies = jiffies;
	item->tptotalbytes = 0;
	item->done = false;
	INIT_LIST_HEAD(&(item->path_bw_list));
	item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	mpip_log("%s, %d\n", __FILE__, __LINE__);
	print_addr(saddr);
	print_addr(daddr);
	mpip_log( "ss: %d,%d,%d\n", item->session_id,
			sport, dport);
	mpip_log("%s, %d\n", __FILE__, __LINE__);
}


//find the session information when receiving a packet.
struct socket_session_table *find_receiver_session(unsigned char *node_id, unsigned char session_id)
{
	struct socket_session_table *socket_session;

	if (!node_id)
		return 0;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
			(socket_session->session_id == session_id))
		{
			return socket_session;
		}
	}

	return NULL;
}

//find the session information when receiving a packet. If it doesn't exist, add a new one.
struct socket_session_table *get_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id,
		 	 	 	 	unsigned char path_id,
		 	 	 	 	unsigned int protocol)
{
	struct socket_session_table *item = NULL;
	int sid;
	int i;

	if (!src_node_id || !dst_node_id || (session_id <= 0))
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	static_session_id = (static_session_id > session_id) ? static_session_id : session_id;

	item = find_receiver_session(dst_node_id, session_id);
	if (item)
		return item;

	mpip_log("%s, %d\n", __FILE__, __LINE__);
	print_addr(saddr);
	print_addr(daddr);
	mpip_log("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

	item = get_sender_session(saddr, sport, daddr, dport, protocol);
	if (item)
		return item;

	if (path_id > 0)
		return NULL;

	item = kzalloc(sizeof(struct socket_session_table), GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

//	INIT_LIST_HEAD(&(item->tcp_buf));
	for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
	{
		item->tcp_buf[i].seq = 0;
		item->tcp_buf[i].skb = NULL;
	}
	item->next_seq = 0;
	item->buf_count = 0;
	item->max_buf_count = MPIP_TCP_BUF_MAX_LEN;
	item->protocol = protocol;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->tphighest = 0;
	item->tprealtime = 0;
	item->tpstartjiffies = jiffies;
	item->tpbwjiffies = jiffies;
	item->tpinitjiffies = jiffies;
	item->tptotalbytes = 0;
	item->done = false;
	INIT_LIST_HEAD(&(item->path_bw_list));
	item->session_id = session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	return item;
}

//get session info from ss_head,
int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct socket_session_table *socket_session;

	if (!node_id || (session_id <= 0))
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
				(socket_session->session_id == session_id))
		{
			*saddr = socket_session->saddr;
			*daddr = socket_session->daddr;
			*sport = socket_session->sport;
			*dport = socket_session->dport;
			return 1;
		}
	}

	return 0;
}

//find session info from ss_head
struct socket_session_table *find_socket_session(unsigned char session_id)
{
	struct socket_session_table *socket_session;

	if (session_id <= 0)
		return NULL;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (socket_session->session_id == session_id)
		{
			return socket_session;
		}
	}

	return NULL;

}

//each session maintain the bandwidth of all paths that belong to this session. 
//This method updates that list.
void update_path_bw_list(struct socket_session_table *socket_session)
{
	struct path_bw_info *path_bw = NULL;
	struct path_bw_info *tmp_path = NULL;
	struct path_info_table *path_info = NULL;


	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id == socket_session->session_id)
		{
			bool done = false;
			list_for_each_entry(path_bw, &(socket_session->path_bw_list), list)
			{
				if (path_bw->path_id == path_info->path_id)
				{
					done = true;
					path_bw->bw = path_info->bw;
				}
			}

			if (done)
				continue;

			struct path_bw_info *item = kzalloc(sizeof(struct path_bw_info), GFP_ATOMIC);
			if (!item)
				return;

			item->path_id = path_info->path_id;
			item->bw = path_info->bw;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(socket_session->path_bw_list));
		}
	}
}

//add total number of bytes transmitted on one session
void add_session_totalbytes(unsigned char session_id, unsigned int len)
{
	struct socket_session_table *socket_session = find_socket_session(session_id);

	if(!socket_session)
		return;

	socket_session->tptotalbytes += len;
}

//update the real time throughput of one path
void update_path_tp(struct path_info_table *path)
{
	if(!path)
		return;

	unsigned long tp = path->tptotalbytes / ((jiffies - path->tpstartjiffies) * 1000 / HZ);
	path->tp = tp;
	path->tptotalbytes = 0;

}

//update the throughput of one session
void update_session_tp(unsigned char session_id, unsigned int len)
{
	struct socket_session_table *socket_session = find_socket_session(session_id);

	if(!socket_session)
		return;

	unsigned long tp = socket_session->tptotalbytes / ((jiffies - socket_session->tpstartjiffies) * 1000 / HZ);
	socket_session->tprealtime = tp;
	if (tp > socket_session->tphighest)
	{
		socket_session->tphighest = tp;
		update_path_bw_list(socket_session);
	}

	socket_session->tptotalbytes = 0;
	socket_session->tpstartjiffies = jiffies;

}

//whenever receiving one packet, check whether it is out of order. If yes, insert into the buffer.
int add_to_tcp_skb_buf(struct sk_buff *skb, unsigned char session_id)
{
	//todo: dynamic MPIP_TCP_BUF_LEN

	struct tcphdr *tcph = NULL;
	struct socket_session_table *socket_session;
	struct tcp_skb_buf *item = NULL;
	struct tcp_skb_buf *tcp_buf = NULL;
	struct tcp_skb_buf *tmp_buf = NULL;

	__u32 tmp_seq = 0;
	__u32 max_seq = 0;
	__u32 min_seq = 0;
	int i;
	int index;
	int sta = 0;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (socket_session->session_id == session_id && (session_id != 0) )
		{
	  		// rcu_read_lock();
			tcph = tcp_hdr(skb);
			if (!tcph)
			{
				mpip_log("%s, %d\n", __FILE__, __LINE__);
				// rcu_read_unlock();
				goto fail;
			}

			if ((ntohl(tcph->seq) < socket_session->next_seq) &&
				(socket_session->next_seq) - ntohl(tcph->seq) < 0xFFFFFFF)
			{
				mpip_log("late: %d %u, %u, %s, %d\n", socket_session->buf_count,
						ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				// dst_input(skb);
				// rcu_read_unlock();
				goto fail;
			}

			if ((socket_session->next_seq == 0) ||
				(ntohl(tcph->seq) == socket_session->next_seq) ||
				(ntohl(tcph->seq) == socket_session->next_seq + 1)) //for three-way handshake
			{
				// rcu_read_lock();
				mpip_log("send: %d, %u, %u, %s, %d\n", socket_session->buf_count,
						ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				socket_session->next_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
				dst_input(skb);

//				bool come = false;
//				int come_buf_count = socket_session->buf_count;
				// *************************************************

recursive:
				if (socket_session->buf_count > 0)
				{
					for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
					{
						if (socket_session->tcp_buf[i].seq == 0)
							continue;

						if (socket_session->tcp_buf[i].seq == socket_session->next_seq)
						{
							socket_session->next_seq = socket_session->tcp_buf[i].skb->len
													- ip_hdr(socket_session->tcp_buf[i].skb)->ihl * 4
													- tcp_hdr(socket_session->tcp_buf[i].skb)->doff * 4
													+ socket_session->tcp_buf[i].seq;

							mpip_log("push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
									socket_session->tcp_buf[i].seq,
									socket_session->next_seq,
									__FILE__, __LINE__);

							dst_input(socket_session->tcp_buf[i].skb);

							socket_session->tcp_buf[i].seq = 0;
							socket_session->tcp_buf[i].skb = NULL;
							socket_session->buf_count -= 1;

//							come = true;

							goto recursive;

						}
					}
				}
				// ******************************************
// recursive:
// 				if (socket_session->buf_count > 0)
// 				{
// 					for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
// 					{
// 						if (socket_session->tcp_buf[i].seq == 0)
// 							continue;

// 						dst_input(socket_session->tcp_buf[i].skb);

// 						if (socket_session->tcp_buf[i].seq >= socket_session->next_seq)
// 						{
// 							socket_session->next_seq = socket_session->tcp_buf[i].skb->len
// 													- ip_hdr(socket_session->tcp_buf[i].skb)->ihl * 4
// 													- tcp_hdr(socket_session->tcp_buf[i].skb)->doff * 4
// 													+ socket_session->tcp_buf[i].seq;

// 							mpip_log("push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
// 									socket_session->tcp_buf[i].seq,
// 									socket_session->next_seq,
// 									__FILE__, __LINE__);


// 							socket_session->tcp_buf[i].seq = 0;
// 							socket_session->tcp_buf[i].skb = NULL;
// 							socket_session->buf_count -= 1;

// //							come = true;

// 							// goto recursive;

// 						}
// 					}
// 				}
				// ******************************************
				// rcu_read_unlock();

//				if (come)
//				{
//					socket_session->max_buf_count = (9 * socket_session->max_buf_count + come_buf_count) / 10;
//					if (socket_session->max_buf_count > MPIP_TCP_BUF_MAX_LEN)
//						socket_session->max_buf_count = MPIP_TCP_BUF_MAX_LEN;
//
//					if (socket_session->max_buf_count < MPIP_TCP_BUF_MIN_LEN)
//						socket_session->max_buf_count = MPIP_TCP_BUF_MIN_LEN;
//
//					mpip_log("change max_buf_count: %d, %d, %s, %d\n", socket_session->max_buf_count,
//							come_buf_count,
//							__FILE__, __LINE__);
//				}
				goto success;
			}
			else
			{
				// ************************************************************8
				if (socket_session->buf_count == MPIP_TCP_BUF_MAX_LEN)
				{
					tmp_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
					if (tmp_seq > max_seq)
					{
						max_seq = tmp_seq;
					}
					// rcu_read_lock();

					dst_input(skb);

					
					for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
					{
						if (socket_session->tcp_buf[i].skb == NULL)
							continue;

						mpip_log("force push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
								socket_session->tcp_buf[i].seq,
								socket_session->next_seq,
								__FILE__, __LINE__);

						tmp_seq = socket_session->tcp_buf[i].skb->len
								- ip_hdr(socket_session->tcp_buf[i].skb)->ihl * 4
								- tcp_hdr(socket_session->tcp_buf[i].skb)->doff * 4
								+ socket_session->tcp_buf[i].seq;

						if (tmp_seq > max_seq)
						{
							max_seq = tmp_seq;
						}

						dst_input(socket_session->tcp_buf[i].skb);
						// kfree_skb(socket_session->tcp_buf[i].skb);


						socket_session->tcp_buf[i].seq = 0;
						socket_session->tcp_buf[i].skb = NULL;
						socket_session->buf_count -= 1;
					}


					socket_session->buf_count = 0;
					socket_session->next_seq = max_seq;
				// *******************************************************
				// modi
// 				if (socket_session->buf_count == MPIP_TCP_BUF_MAX_LEN)
// 				{
// 					// tmp_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
// 					// if (tmp_seq > max_seq)
// 					// {
// 						max_seq = ntohl(tcph->seq);
// 						sta = 1;
// 						index = -1;
// 					// }
// 					// rcu_read_lock();

// 					// dst_input(skb);

					
// 					for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
// 					{
// 						if (socket_session->tcp_buf[i].seq == 0)
// 							continue;

// 						mpip_log("force push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
// 								socket_session->tcp_buf[i].seq,
// 								socket_session->next_seq,
// 								__FILE__, __LINE__);

// 						// tmp_seq = socket_session->tcp_buf[i].skb->len
// 						// 		- ip_hdr(socket_session->tcp_buf[i].skb)->ihl * 4
// 						// 		- tcp_hdr(socket_session->tcp_buf[i].skb)->doff * 4
// 						// 		+ socket_session->tcp_buf[i].seq;

// 						if (socket_session->tcp_buf[i].seq > max_seq)
// 						{
// 							max_seq = socket_session->tcp_buf[i].seq;
// 							index = i;

// 						}


// 						// dst_input(socket_session->tcp_buf[i].skb);
// 						// // kfree_skb(socket_session->tcp_buf[i].skb);


// 						// socket_session->tcp_buf[i].seq = 0;
// 						// socket_session->tcp_buf[i].skb = NULL;
// 						// socket_session->buf_count -= 1;
// 					}
// 					if(index == -1)
// 					{
// 						tmp_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
// 					}
// 					else
// 					{
// 						tmp_seq = socket_session->tcp_buf[index].skb->len
// 								- ip_hdr(socket_session->tcp_buf[index].skb)->ihl * 4
// 								- tcp_hdr(socket_session->tcp_buf[index].skb)->doff * 4
// 								+ socket_session->tcp_buf[index].seq;
	
// 					}
					
// force:
// 					if(socket_session->buf_count > 0)
// 					{
// 						min_seq = max_seq;
// 						for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
// 						{
// 							if (socket_session->tcp_buf[i].seq == 0)
// 								continue;

// 							// mpip_log("force push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
// 							// 		socket_session->tcp_buf[i].seq,
// 							// 		socket_session->next_seq,
// 							// 		__FILE__, __LINE__);

// 							// tmp_seq = socket_session->tcp_buf[i].skb->len
// 							// 		- ip_hdr(socket_session->tcp_buf[i].skb)->ihl * 4
// 							// 		- tcp_hdr(socket_session->tcp_buf[i].skb)->doff * 4
// 							// 		+ socket_session->tcp_buf[i].seq;

// 							if (socket_session->tcp_buf[i].seq < min_seq)
// 							{
// 								min_seq = socket_session->tcp_buf[i].seq;
// 								index = i;

// 							}
// 							// dst_input(socket_session->tcp_buf[i].skb);
// 							// // kfree_skb(socket_session->tcp_buf[i].skb);


// 							// socket_session->tcp_buf[i].seq = 0;
// 							// socket_session->tcp_buf[i].skb = NULL;
// 							// socket_session->buf_count -= 1;
// 						}

// 						if(sta == 1)
// 						{
// 							if(min_seq >= socket_session->tcp_buf[i].seq)
// 							{
// 								dst_input(skb);
// 								sta = 0;
// 							}
// 							else
// 							{
// 								dst_input(socket_session->tcp_buf[index].skb);
// 								socket_session->tcp_buf[index].seq = 0;
// 								socket_session->tcp_buf[index].skb = NULL;
// 								socket_session->buf_count -= 1;
// 							}
// 						}
// 						else
// 						{
// 							dst_input(socket_session->tcp_buf[index].skb);
// 							socket_session->tcp_buf[index].seq = 0;
// 							socket_session->tcp_buf[index].skb = NULL;
// 							socket_session->buf_count -= 1;
// 						}
// 						goto force;
// 					}


// 					socket_session->buf_count = 0;
// 					socket_session->next_seq = tmp_seq;
					// rcu_read_unlock();
					// modi
					// *************************************************************
					goto success;
				}
				else
				{
					// rcu_read_lock();
					for (i = 0; i < MPIP_TCP_BUF_MAX_LEN; ++i)
					{
						if (socket_session->tcp_buf[i].seq == 0)
						{
							socket_session->tcp_buf[i].seq = ntohl(tcph->seq);
							socket_session->tcp_buf[i].skb = skb;
							socket_session->buf_count += 1;

							mpip_log("out of order: %d, %u, %u, %s, %d\n",
									socket_session->buf_count,
									ntohl(tcph->seq), socket_session->next_seq,
									__FILE__, __LINE__);
							// rcu_read_unlock();
							// kfree_skb(skb); 
							goto success;
						}
					}
					// rcu_read_unlock();				
				}
			}
		}
	}


fail:
	// rcu_read_unlock();
	// mpip_log("Fail: %s, %d\n", __FILE__, __LINE__);
	return 0;

success:
	// rcu_read_unlock();
	return 1;
}

//find path_inf_table from pi_head.
struct path_info_table *find_path_info(__be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport, unsigned char session_id)
{
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->saddr == saddr) &&
			(path_info->daddr == daddr) &&
			(path_info->sport == sport) &&
			(path_info->dport == dport) &&
			(path_info->session_id == session_id))
		{
			return path_info;
		}
	}
	return NULL;
}

//start the three way handshake
bool init_mpip_tcp_connection(struct sk_buff *skb,
							__be32 daddr1, __be32 daddr2,
							__be32 saddr, __be32 daddr,
							__be16 sport, __be16 dport,
							unsigned char session_id)
{

	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
	list_for_each_entry(local_addr, &la_head, list)
	{
		if (local_addr->addr == saddr)
		{
			if (daddr1 == daddr)
			{
				if ((daddr2 != 0) && !find_path_info(local_addr->addr, daddr2, sport + 1, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 1, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr2);

					send_mpip_syn(skb, local_addr->addr, daddr2,
							sport + 1, dport, true, false, session_id);
				}
			}
			else
			{
				if ((daddr1 != 0) && !find_path_info(local_addr->addr, daddr1, sport + 1, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 1, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr1);

					send_mpip_syn(skb, local_addr->addr, daddr1,
							sport + 1, dport, true, false, session_id);
				}
			}
		}
		else
		{
			if(check_bad_addr(local_addr->addr)) {
				if ((daddr1 != 0) && !find_path_info(local_addr->addr, daddr1, sport + 2, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 2, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr1);

					send_mpip_syn(skb, local_addr->addr, daddr1,
							sport + 2, dport, true, false, session_id);
				}

				if ((daddr2 != 0) && !find_path_info(local_addr->addr, daddr2, sport + 3, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 3, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr2);

					send_mpip_syn(skb, local_addr->addr, daddr2,
							sport + 3, dport, true, false, session_id);
				}
			}
		}
	}

	return true;
}

//check whether the original path has been added into pi_head.
//This is for the fake TCP
bool is_origin_path_info_added(unsigned char *node_id, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *path_info;

	if (!node_id || (session_id <= 0))
		return false;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->session_id == session_id))
		{
			return true;
		}
	}

	return false;
}

//add the original path into pi_head for tcp.
int add_origin_path_info_tcp(unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *item = NULL;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (is_origin_path_info_added(node_id, session_id, protocol))
		return 0;

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

	item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	INIT_LIST_HEAD(&(item->mpip_log));
	item->tp = 0;
	item->tpstartjiffies = jiffies;
	item->tptotalbytes = 0;
	item->fbjiffies = jiffies;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	item->min_delay = -1;
	item->max_delay = -1;
	item->delay = 0;
	item->queuing_delay = 0;
	item->max_queuing_delay = -1;
	item->count = 0;
	item->bw = 250;
	item->pktcount = 0;
	item->logcount = 0;
	item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;

	if (is_original_path(node_id, item->saddr, item->daddr,
			item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
	{
		item->status = 0;
	}
	else
	{
		item->status = 0;
	}

	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &pi_head);

	return 1;
}

//add path info into pi_head for tcp
//TCP and UDP have different proces.
int add_path_info_tcp(int id, unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *item = NULL;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	item = find_path_info(saddr, daddr,
				sport, dport, session_id);

	if (item)
	{
		item->status = 0;
		return true;
	}

	item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	INIT_LIST_HEAD(&(item->mpip_log));
	item->tp = 0;
	item->tpstartjiffies = jiffies;
	item->tptotalbytes = 0;
	item->fbjiffies = jiffies;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	item->min_delay = -1;
	item->max_delay = -1;
	item->delay = 0;
	item->queuing_delay = 0;
	item->max_queuing_delay = -1;
	item->count = 0;
	item->bw = 250;
	item->pktcount = 0;
	item->logcount = 0;
	item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
	item->status = 0;

	mpip_log("%d, %d, %d, %d, %d: %s, %s, %d\n", id, static_path_id, session_id, sport, dport, __FILE__, __FUNCTION__, __LINE__);
//	print_addr_1(saddr);
//	print_addr_1(daddr);


//	if (is_original_path(node_id, item->saddr, item->daddr,
//			item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
//	{
//		item->status = 0;
//	}
//	else
//	{
//		item->status = 0;
//	}

	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &pi_head);

	return 1;
}

//set the status of the path to 0, make it ready
bool ready_path_info(int id, unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id)
{
	struct path_info_table *path_info = find_path_info(saddr, daddr,
			sport, dport, session_id);

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (path_info)
	{
		path_info->status = 0;
		return true;
	}
	else
	{
		if (add_path_info_tcp(id, node_id, saddr, daddr, sport, dport, session_id, IPPROTO_TCP))
			return true;
	}

	return false;
}

//check whether one path has been added into pi_head
bool is_dest_added(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *path_info;

	if (!node_id)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->daddr == addr) &&
		   (path_info->dport == port) &&
		   (path_info->session_id == session_id))
		{
			return true;
		}
	}
	return false;
}

//check wheter one path is the original path
bool is_original_path(unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id)
{
	__be32 osaddr = 0, odaddr = 0;
	__be16 osport = 0, odport = 0;

	if (get_receiver_session_info(node_id, session_id,
			  &osaddr, &osport, &odaddr, &odport))
	{
		if ((saddr == osaddr) && (daddr == odaddr) &&
			(sport == osport) && (dport == odport))
		{
			return true;
		}
	}

	return false;
}

//add path info into pi_head for UDP.
//TCP and UDP have different proces.
int add_path_info_udp(unsigned char *node_id, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
//	__be32 waddr = convert_addr(192, 168, 2, 20);
//	__be32 eaddr = convert_addr(192, 168, 2, 21);

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}
//
//	if (is_dest_added(node_id, daddr, dport, session_id, protocol))
//		return 0;

	if (!check_bad_addr(daddr))
		return 0;

	list_for_each_entry(local_addr, &la_head, list)
	{

		item = find_path_info(local_addr->addr, daddr,
						sport, dport, session_id);
		if (item)
		{
			item->status = 0;
			continue;
		}


		// if(daddr>>24 & 0xff != local_addr->addr>>24 & 0xff)
		// {
		// 	continue;
		// }

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
		INIT_LIST_HEAD(&(item->mpip_log));
		item->tp = 0;
		item->tpstartjiffies = jiffies;
		item->tptotalbytes = 0;
		item->fbjiffies = jiffies;
		item->saddr = local_addr->addr;
		item->sport = sport;
		item->daddr = daddr;
		item->dport = dport;
		item->session_id = session_id;
		item->min_delay = -1;
		item->max_delay = -1;
		item->delay = 0;
		item->queuing_delay = 0;
		item->max_queuing_delay = 0;
		item->count = 0;
		item->bw = 250;
		item->pktcount = 0;
		item->logcount = 0;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;

		if (is_original_path(node_id, item->saddr, item->daddr,
				item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
		{
			item->status = 0;
		}
		else
		{
			item->status = 0;
		}

		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &pi_head);

//		mpip_log( "pi: %d\n", item->path_id);
//
//		print_node_id(__FUNCTION__, node_id);
//		print_addr(__FUNCTION__, addr);
	}

	return 1;
}

//find the path with the lowest delay. This is for the customized routing
struct path_info_table *find_lowest_delay_path(unsigned char *node_id,
		unsigned char session_id)
{
	struct path_info_table *path_info;
	struct path_info_table *f_path = NULL;
	__s32 min_delay = -1;


	if (session_id <= 0)
		return NULL;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (!is_equal_node_id(path_info->node_id, node_id) ||
				path_info->session_id != session_id ||
				path_info->status != 0 || path_info->bw ==0 )
		{
			continue;
		}

		if (path_info->delay < min_delay || min_delay == -1)
		{
			min_delay = path_info->delay;
			f_path = path_info;
		}
	}

	return f_path;
}

//log
void add_mpip_log(unsigned char session_id)
{
	struct path_info_table *path_info;

	if (session_id <= 0)
		return;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
		{
			continue;
		}

		struct mpip_log_table* item = kzalloc(sizeof(struct mpip_log_table), GFP_ATOMIC);
		if (!item)
			return;

		item->logjiffies = jiffies;
		item->delay = path_info->delay;
		item->min_delay = path_info->min_delay;
		item->queuing_delay = path_info->queuing_delay;
		item->tp = path_info->tp;
		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &(path_info->mpip_log));
		path_info->logcount += 1;

//		if (s_s_id == 0)
//		{
//			s_s_id = session_id;
//			s_p_id = path_info->path_id;
//		}
//		if ((session_id == s_s_id) && (path_info->path_id == s_p_id))
//		{
//			printk("%d,%d,%lu,%d,%d,%d,%d,%lu\n", session_id, path_info->path_id,
//												jiffies,
//												path_info->delay,
//												path_info->min_delay,
//												path_info->delay - path_info->min_delay,
//												path_info->queuing_delay,
//												path_info->tp);
//		}
//		printk("%s, %d\n", __FILE__, __LINE__);
	}

}

//dreprecated. write log into file has performance issues.
void write_mpip_log_to_file(unsigned char session_id)
{
	struct path_info_table *path_info;
	struct mpip_log_table *mpip_log;
	struct mpip_log_table *tmp_mpip;
	mm_segment_t old_fs;
	struct file* fp = NULL;
	loff_t pos;

	if (session_id <= 0)
		return;

	if (sysctl_mpip_rcv)
		return;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
		{
			continue;
		}

		printk("******start: %d %d******\n", session_id, path_info->path_id);
		list_for_each_entry(mpip_log, &(path_info->mpip_log), list)
		{

			printk("%d,%d,%lu,%d,%d,%d,%d,%lu\n", session_id, path_info->path_id,
										mpip_log->logjiffies,
										mpip_log->delay,
										mpip_log->min_delay,
										mpip_log->delay - mpip_log->min_delay,
										mpip_log->queuing_delay,
										mpip_log->tp);

		}
		printk("******end: %d %d******\n", session_id, path_info->path_id);

		list_for_each_entry_safe(mpip_log, tmp_mpip, &(path_info->mpip_log), list)
		{
			list_del(&(mpip_log->list));
			kfree(mpip_log);
		}
		INIT_LIST_HEAD(&(path_info->mpip_log));
		path_info->logcount = 0;
	}


}

//find the best path to send out the packet. 
//This method is very important. It choose the path according to the customized routing
//also, the random number is generated here.
unsigned char find_fastest_path_id(unsigned char *node_id,
			   __be32 *saddr, __be32 *daddr,  __be16 *sport, __be16 *dport,
			   __be32 origin_saddr, __be32 origin_daddr, __be16 origin_sport,
			   __be16 origin_dport, unsigned char session_id,
			   unsigned int protocol, unsigned int len, bool is_short)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;

	__u64 totalbw = 0, tmptotal = 0, f_bw = 0;
	int random = 0;
	bool path_done = true;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	struct socket_session_table *socket_session = find_socket_session(session_id);

	if(socket_session)
	{
		if (((jiffies - socket_session->tpinitjiffies) * 1000 / HZ) >= sysctl_mpip_exp_time)
		{
			socket_session->done = true;
			write_mpip_log_to_file(session_id);
			socket_session->tpinitjiffies = jiffies;
		}
		if (!(socket_session->done) &&
				((jiffies - socket_session->tpstartjiffies) * 1000 / HZ) >= sysctl_mpip_tp_time)
		{
			update_session_tp(session_id, len);
			socket_session->tpstartjiffies = jiffies;
			add_mpip_log(session_id);
		}
		if (((jiffies - socket_session->tpbwjiffies) * 1000 / HZ) >= sysctl_mpip_bw_time)
		{
			update_path_info(session_id);
			socket_session->tpbwjiffies = jiffies;
		}
	}

//	int priority = get_pkt_priority(origin_daddr, origin_dport, protocol,
//									len);
//
//	if (priority = MPIP_DELAY_PRIORITY)
//	{
//		is_short = true;
//	}
//	else
//	{
//		is_short = false;
//	}
	
	if ((origin_daddr != 5001 || origin_daddr != 5201 ) && sysctl_mpip_skype)
	{
	    f_path = find_lowest_delay_path(node_id, session_id);

		   if (f_path)
		   {
			   *saddr = f_path->saddr;
			   *daddr = f_path->daddr;
			   *sport = f_path->sport;
			   *dport = f_path->dport;
			   f_path->pktcount += 1;
			   f_path_id = f_path->path_id;

		       goto ret;

	    }
	}

	if ((origin_daddr == 5001 || origin_daddr == 5201 ) && sysctl_mpip_skype)
	{
		f_path = find_lowest_delay_path(node_id, session_id);

		if (f_path)
		{
			list_for_each_entry(path, &pi_head, list)
			{
				if (!is_equal_node_id(path->node_id, node_id) ||
					path->session_id != session_id ||
					path->status != 0|| path->path_id == f_path->path_id)
				{
					continue;
				}
				totalbw += path->bw;
				if (path->bw > f_bw)
				{
					f_bw = path->bw;
					f_path_id = path->path_id;
					f_path = path;
				}
				if (path->delay == 0)
					path_done = false;
			}

			if (totalbw > 0)
			{
				random = get_random_int() % totalbw;
				random = (random > 0) ? random : -random;
				tmptotal = 0;

				list_for_each_entry(path, &pi_head, list)
				{
					if (!is_equal_node_id(path->node_id, node_id) ||
						path->session_id != session_id ||
						path->status != 0)
					{
						continue;
					}

					if (random < (path->bw + tmptotal))
					{
						f_path_id = path->path_id;
						f_path = path;

						break;
					}
					else
					{
						tmptotal += path->bw;
					}
				}
			}

			if (f_path_id > 0)
			{
				*saddr = f_path->saddr;
				*daddr = f_path->daddr;
				*sport = f_path->sport;
				*dport = f_path->dport;
				f_path->pktcount += 1;
			}
			else
			{
				f_path = find_path_info(origin_saddr, origin_daddr, origin_sport, origin_dport, session_id);
				if (f_path)
				{
					*saddr = f_path->saddr;
					*daddr = f_path->daddr;
					*sport = f_path->sport;
					*dport = f_path->dport;
					f_path->pktcount += 1;

					f_path_id = f_path->path_id;
				}
			}
			goto ret;
	    }
	}



	// for ack packet, use the path with lowest delay
	if (is_short && sysctl_mpip_skype)
	{
		f_path = find_lowest_delay_path(node_id, session_id);

		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			*sport = f_path->sport;
			*dport = f_path->dport;
			f_path->pktcount += 1;
			f_path_id = f_path->path_id;

			goto ret;

		}
	}


	//if comes here, it means all paths have been probed
	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id) ||
			path->session_id != session_id ||
			path->status != 0)
		{
			continue;
		}

// for depreciated path
//		if ((jiffies - path->fbjiffies) / HZ >= sysctl_mpip_hb * 5)
//			continue;

		totalbw += path->bw;

		if (path->bw > f_bw)
		{
			f_bw = path->bw;
			f_path_id = path->path_id;
			f_path = path;
		}

		if (path->delay == 0)
			path_done = false;
	}

	//if ((totalbw > 0) || !path_done)
	if (totalbw > 0)
	{
		random = get_random_int() % totalbw;
		random = (random > 0) ? random : -random;
		tmptotal = 0;

		list_for_each_entry(path, &pi_head, list)
		{
			if (!is_equal_node_id(path->node_id, node_id) ||
				path->session_id != session_id ||
				path->status != 0)
			{
				continue;
			}

			if (random < (path->bw + tmptotal))
			{
				f_path_id = path->path_id;
				f_path = path;

				break;
			}
			else
			{
				tmptotal += path->bw;
			}
		}
	}

	if (f_path_id > 0)
	{
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;
		*sport = f_path->sport;
		*dport = f_path->dport;
		f_path->pktcount += 1;
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr, origin_sport, origin_dport, session_id);
		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			*sport = f_path->sport;
			*dport = f_path->dport;
			f_path->pktcount += 1;

			f_path_id = f_path->path_id;
		}
	}

ret:
	if (f_path)
	{
		f_path->tptotalbytes += len;
		if (((jiffies - f_path->tpstartjiffies) * 1000 / HZ) >= sysctl_mpip_bw_time)
		{
			update_path_tp(f_path);
			f_path->tpstartjiffies = jiffies;
		}
	}

	return f_path_id;
}

//send heartbeat
void send_mpip_hb(struct sk_buff *skb, unsigned char session_id)
{
	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

	if (((jiffies - earliest_fbjiffies) * 1000 / HZ) >= sysctl_mpip_hb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (send_mpip_msg(skb, false, true, MPIP_HB_FLAGS, session_id))
			earliest_fbjiffies = jiffies;
	}
}

//decide which path to feedback
unsigned char find_earliest_path_stat_id(unsigned char *dest_node_id, unsigned char session_id, __s32 *delay)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = 0;
	unsigned long e_fbtime = jiffies;
//	int totalrcv = 0;
//	int max_rcvc = 0;

	if (!dest_node_id || session_id <= 0)
		return 0;


	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (!is_equal_node_id(path_stat->node_id, dest_node_id) ||
			path_stat->session_id != session_id)
		{
			continue;
		}

		//if (!path_stat->feedbacked && path_stat->fbjiffies <= e_fbtime)
		if (path_stat->fbjiffies <= e_fbtime)
		{
			e_path_stat_id = path_stat->path_id;
			e_path_stat = path_stat;
			e_fbtime = path_stat->fbjiffies;
		}
	}

	if (e_path_stat_id > 0)
	{
		e_path_stat->fbjiffies = jiffies;
		e_path_stat->feedbacked = true;
		earliest_fbjiffies = jiffies;

		*delay = e_path_stat->delay;

		//e_path_stat->delay = 0;

	}

	return e_path_stat_id;
}


//get find local address. Mainly for deciding whether this address is local address.
__be32 find_local_addr(__be32 addr)
{
	struct local_addr_table *local_addr;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (local_addr->addr == addr)
		{
			return local_addr->addr;
		}
	}

	return 0;
}

//get the available ip addresses list locally that can be used to send out
//Internet packets
void get_available_local_addr(void)
{
	struct net_device *dev;
	struct local_addr_table *item = NULL;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (strstr(dev->name, "wlan1"))
			continue;

		if (strstr(dev->name, "dock"))
			continue;		

		if (!netif_running(dev)|| !netif_carrier_ok(dev))
		{
			if (dev->ip_ptr && dev->ip_ptr->ifa_list)
			{
				mpip_log( "un-active: %lu  ", dev->state);
				// print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
			}

			continue;
		}
		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &la_head);
			mpip_log( "local addr: %lu  ", dev->state);
			// print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
		}
	}
}

//when ip address changes, reset relative tables.
void update_addr_change(unsigned long event)
{
	// reset_mpip();
	// return;
	__be32 addr1 =0, addr2 = 0;
	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;
	// struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct path_info_table *tmp_info;
	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

	struct addr_notified_table *addr_notified;

	list_for_each_entry(addr_notified, &an_head, list)
	{
		addr_notified->notified = false;
	}

	list_for_each_entry_safe(local_addr, tmp_addr, &la_head, list)
	{
		list_del(&(local_addr->list));
		kfree(local_addr);
	}

	get_available_local_addr();

	addr1 = get_local_addr1();
	addr2 = get_local_addr2();
	print_addr(addr1);
	print_addr(addr2);

	// if(event == NETDEV_DOWN){
	// 	mpip_log("down\n");
	// 	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	// 	{
	// 		if((path_info->saddr != addr1) && (path_info->saddr != addr2)) {	
	// 			// list_del(&(path_info->list));
	// 			// kfree(path_info);
	// 			path_info->bw = 0;
	// 		}
	// 	}
		
	// 	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

	// }

	// if(event == NETDEV_UP){
	if (!check_bad_addr(addr1) || !check_bad_addr(addr2)){
		mpip_log("down\n");
		rcu_read_lock();
		list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
		{
			if((path_info->saddr != addr1) && (path_info->saddr != addr2)) {	
				list_del(&(path_info->list));
				kfree(path_info);
				// path_info->status = 4;
				// path_info->bw = 0;
			}
		}
		// list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
		// {
		// 	if((path_info->saddr != addr1) && (path_info->saddr != addr2)) {	
		// 		list_del(&(path_stat->list));
		// 		kfree(path_stat);
		// 	}
		// }
		rcu_read_unlock();

		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	}
	else {
		mpip_log("up\n");
		rcu_read_lock();
		list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
		{
			list_del(&(path_info->list));
			kfree(path_info);
		}

		list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
		{
			list_del(&(path_stat->list));
			kfree(path_stat);
		}
		rcu_read_unlock();

		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	}	


	// }

	// list_for_each_entry(working_ip, &wi_head, list)
	// {
	// 	list_del(&(working_ip->list));
	// 	kfree(working_ip);
	// 	// add_path_info(working_ip->node_id, working_ip->addr, working_ip->port,
	// 	// 		working_ip->session_id, working_ip->protocol);
	// }

	


	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
}

//find the ehternet card with ip address.
struct net_device *find_dev_by_addr(__be32 addr)
{
	struct net_device *dev;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (!netif_running(dev)||!(netif_carrier_ok(dev)))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (dev->ip_ptr->ifa_list->ifa_address == addr)
				return dev;
		}
	}
	return NULL;
}

//reset everything
void reset_mpip(void)
{
	struct mpip_enabled_table *mpip_enabled;
	struct mpip_enabled_table *tmp_enabled;

	struct addr_notified_table *addr_notified;
	struct addr_notified_table *tmp_notified;

	struct working_ip_table *working_ip;
	struct working_ip_table *tmp_ip;

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;
	struct mpip_log_table *mpip_log;
	struct mpip_log_table *tmp_mpip;

	struct socket_session_table *socket_session;
	struct socket_session_table *tmp_session;
	struct path_bw_info *path_bw;
	struct path_bw_info *tmp_bw;
	struct tcp_skb_buf *tcp_buf;
	struct tcp_skb_buf *tmp_buf;

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;


	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;

	struct route_rule_table *route_rule;
	struct route_rule_table *tmp_rule;

	list_for_each_entry_safe(mpip_enabled, tmp_enabled, &me_head, list)
	{
			list_del(&(mpip_enabled->list));
			kfree(mpip_enabled);
	}

	list_for_each_entry_safe(addr_notified, tmp_notified, &an_head, list)
	{
			list_del(&(addr_notified->list));
			kfree(addr_notified);
	}

	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
	{
			list_del(&(working_ip->list));
			kfree(working_ip);
	}

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		list_for_each_entry_safe(mpip_log, tmp_mpip, &(path_info->mpip_log), list)
		{
			list_del(&(mpip_log->list));
			kfree(mpip_log);
		}

		list_del(&(path_info->list));
		kfree(path_info);
	}

	list_for_each_entry_safe(socket_session, tmp_session, &ss_head, list)
	{
		list_for_each_entry_safe(path_bw, tmp_bw, &(socket_session->path_bw_list), list)
		{
			list_del(&(path_bw->list));
			kfree(path_bw);
		}

		list_del(&(socket_session->list));
		kfree(socket_session);
	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
			list_del(&(path_stat->list));
			kfree(path_stat);
	}

	list_for_each_entry_safe(local_addr, tmp_addr, &la_head, list)
	{
			list_del(&(local_addr->list));
			kfree(local_addr);
	}

	list_for_each_entry_safe(route_rule, tmp_rule, &rr_head, list)
	{
			list_del(&(route_rule->list));
			kfree(route_rule);
	}

	static_session_id = 1;
	static_path_id = 1;

	s_s_id = 0;
	s_p_id = 0;


	global_stat_1 = 0;
	global_stat_2 = 0;
	global_stat_3 = 0;

}

//implement sys call for printing all tables into terminal. 
//Sys calls can be called at application layer with bash shell script
asmlinkage long sys_mpip(void)
{
	struct mpip_enabled_table *mpip_enbaled;
	struct mpip_query_table *mpip_query;
	struct addr_notified_table *addr_notified;
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct socket_session_table *socket_session;
	struct path_bw_info *path_bw;
	struct path_stat_table *path_stat;
	struct local_addr_table *local_addr;
	struct route_rule_table *route_rule;
	char *p;


	printk("******************la*************\n");
	list_for_each_entry(local_addr, &la_head, list)
	{
		p = (char *) &(local_addr->addr);
		printk( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	}

	printk("******************me*************\n");
	list_for_each_entry(mpip_enbaled, &me_head, list)
	{
		p = (char *) &(mpip_enbaled->addr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", mpip_enbaled->port);

		printk("%d  ", mpip_enbaled->sent_count);

		printk("%d\n", mpip_enbaled->mpip_enabled);
	}


	printk("******************mq*************\n");
	list_for_each_entry(mpip_query, &mq_head, list)
	{
		p = (char *) &(mpip_query->saddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(mpip_query->saddr);
				printk( "%d.%d.%d.%d  ",
						(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", mpip_query->sport);

		printk("%d\n", mpip_query->dport);
	}

//	printk("******************an*************\n");
//	list_for_each_entry(addr_notified, &an_head, list)
//	{
//		printk( "%02x-%02x  ",
//				addr_notified->node_id[0], addr_notified->node_id[1]);
//
//		printk("%d\n", addr_notified->notified);
//	}

//	printk("******************wi*************\n");
//	list_for_each_entry(working_ip, &wi_head, list)
//	{
//		printk( "%02x-%02x  ",
//				working_ip->node_id[0], working_ip->node_id[1]);
//
//		p = (char *) &(working_ip->addr);
//		printk( "%d.%d.%d.%d  ",
//				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
//
//		printk("%d  ", working_ip->port);
//
//		printk("%d  ", working_ip->session_id);
//
//		printk("%d\n", working_ip->protocol);
//	}

	printk("******************ss*************\n");
	list_for_each_entry(socket_session, &ss_head, list)
	{
		printk( "%02x-%02x  ",
				socket_session->src_node_id[0], socket_session->src_node_id[1]);

		printk( "%02x-%02x  ",
						socket_session->dst_node_id[0], socket_session->dst_node_id[1]);

		printk("%d  ", socket_session->session_id);

		p = (char *) &(socket_session->saddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(socket_session->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", socket_session->sport);

		printk("%d  ", socket_session->dport);

//		printk("%lu  ", socket_session->tpinitjiffies);
//
//		printk("%lu  ", socket_session->tpstartjiffies);
//
//		printk("%lu  ", socket_session->tptotalbytes);
//
//		printk("%lu  ", socket_session->tprealtime);
//
//		printk("%lu  ", socket_session->tphighest);

		printk("%d  ", socket_session->max_buf_count);
		printk("%d\n", socket_session->protocol);

//		list_for_each_entry(path_bw, &(socket_session->path_bw_list), list)
//		{
//			printk("%d:%lu  ", path_bw->path_id, path_bw->bw);
//		}
//		printk("\n");
	}

//	printk("******************ps*************\n");
//	list_for_each_entry(path_stat, &ps_head, list)
//	{
//		printk( "%02x-%02x  ",
//				path_stat->node_id[0], path_stat->node_id[1]);
//
//		printk("%d  ", path_stat->path_id);
//
//		printk("%d  ", path_stat->delay);
//
//		printk("%lu  ", path_stat->fbjiffies);
//
//		printk("%llu\n", path_stat->pktcount);
//	}


	printk("******************pi*************\n");
	list_for_each_entry(path_info, &pi_head, list)
	{
		printk( "%02x-%02x  ",
				path_info->node_id[0], path_info->node_id[1]);

		printk("%d  ", path_info->path_id);

		p = (char *) &(path_info->saddr);

		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(path_info->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

//		printk("%d  ", path_info->sport);
//
//		printk("%d  ", path_info->dport);

		printk("%d  ", path_info->session_id);

		printk("%d  ", path_info->min_delay);

		printk("%d  ", path_info->delay);

		printk("%d  ", path_info->queuing_delay);

//		printk("%d  ", path_info->ave_min_delay);
//		printk("%d  ", path_info->ave_delay);
//		printk("%d  ", path_info->ave_queuing_delay);
		printk("%d  ", path_info->tmp);


//		printk("%lu  ", path_info->tpstartjiffies);
//		printk("%lu  ", path_info->tptotalbytes);
//		printk("%lu  ", path_info->tp);
//		printk("%d  ", path_info->logcount);
		printk("%llu  ", path_info->pktcount);
		printk("%llu\n", path_info->bw);

//		printk("%d\n", path_info->status);

	}


//	printk("******************rr*************\n");
//	list_for_each_entry(route_rule, &rr_head, list)
//	{
//		printk("%s  ", route_rule->dest_addr);
//
//		printk("%s  ", route_rule->dest_port);
//
//		printk("%d  ", route_rule->protocol);
//
//		printk("%d  ", route_rule->startlen);
//
//		printk("%d  ", route_rule->endlen);
//
//		printk("%d\n", route_rule->priority);
//	}
	return 0;

}

//sys call for reset
asmlinkage long sys_reset_mpip(void)
{
	reset_mpip();
	printk("reset ended\n");
	return 0;
}

//sys call for add routing
asmlinkage long sys_add_mpip_route_rule(const char *dest_addr, const char *dest_port,
		int protocol, int startlen,
		int endlen, int priority)
{
	if (!dest_addr || !dest_port)
		return 1;

	add_route_rule(dest_addr, dest_port, protocol, startlen, endlen, priority);

//	printk("%s, %s, %d, %d, %d, %d, %s, %d\n",
//			dest_addr, dest_port, protocol, startlen,endlen,
//			priority, __FILE__, __LINE__);

	printk("add_route_rule ended\n");
	return 0;
}
