#include "ft_nmap.h"

void		no_answer(t_thread *t)
{
	t_target	*tmp;

	tmp = t->targets;
	while (tmp)
	{
		switch (t->scan)
		{
			case SYN:
				if (tmp->res->scans[t->scan] == -1)
					tmp->res->scans[t->scan] = FILT;
				break ;
			case ACK:
				if (tmp->res->scans[t->scan] == -1)
					tmp->res->scans[t->scan] = FILT;
				if (tmp->res->scans[SYN] == OPEN)
					tmp->res->scans[t->scan] = UNF;
				break ;
			default:
				if (tmp->res->scans[t->scan] == -1)
					tmp->res->scans[t->scan] = OPFI;
		}
		tmp = tmp->next;
	}
}

static void	res_icmp(t_thread *thread, char *ip, t_target *t, struct icmp *icmphdr)
{
	if (thread->scan == UDP &&
		icmphdr->icmp_type == 3 &&
		icmphdr->icmp_code == 3)
			t->res->scans[thread->scan] = CLOSE;
	else if (icmphdr->icmp_type == 3 &&
			icmphdr->icmp_code <= 3 ||
			icmphdr->icmp_code == 9 ||
			icmphdr->icmp_code == 10 ||
			icmphdr->icmp_code == 13)
			t->res->scans[thread->scan] = FILT;
}

static void	res_tcp(t_thread *thread, char *ip, t_target *t, struct tcphdr *tcphdr)
{
	switch (thread->scan)
	{
		case SYN:
			if (tcphdr->syn || tcphdr->ack && tcphdr->syn)
				t->res->scans[thread->scan] = OPEN;
			else if (tcphdr->rst)
				t->res->scans[thread->scan] = CLOSE;
		break ;
		case ACK:
			if (tcphdr->rst)
				t->res->scans[thread->scan] = UNF;
		break ;
		default:
			if (tcphdr->rst)
				t->res->scans[thread->scan] = CLOSE;
	}
}

static void	get_res(t_thread *thread, int type, char *ip, struct tcphdr *tcphdr, struct udphdr *udphdr, struct icmp *icmphdr)
{
	t_target		*tmp;
	int			i;

	i = 0;
	tmp = thread->targets;
	while (tmp && i < thread->n_targets)
	{
		if (type == TCP_P && tmp->port == ntohs(tcphdr->source) && !ft_strcmp(ip, tmp->ip))
			break ;
		else if (type == ICMP_P && tmp->port == ntohs(tcphdr->dest) && !ft_strcmp(ip, tmp->ip))
			break ;
		else if (udphdr && tmp->port == ntohs(udphdr->source) && !ft_strcmp(ip, tmp->ip))
			break ;
		tmp = tmp->next;
	}
	if (tmp == NULL)
		return ;
	if (type == ICMP_P)
		res_icmp(thread, ip, tmp, icmphdr);
	else if (type == UDP_P)
		tmp->res->scans[thread->scan] = OPEN;
	else if (type == TCP_P)
		res_tcp(thread, ip, tmp, tcphdr);
}

void		parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
	struct ip	*iphdr;
	struct icmp	*icmphdr;
	struct tcphdr	*tcphdr;
	struct udphdr	*udphdr;
	int		hdr_len1;
	int		hdr_len2;
	t_thread	*thread;
	 
 	thread = (t_thread *)user;
	packetptr += 14;
	iphdr = (struct ip *)packetptr;
	hdr_len1 = iphdr->ip_hl << 2;
	switch (iphdr->ip_p)
	{
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)(packetptr + 4 * iphdr->ip_hl);
			get_res(thread, TCP_P, inet_ntoa(iphdr->ip_src), tcphdr, NULL, NULL);
		break ;
		case IPPROTO_UDP:
			udphdr = (struct udphdr*)(packetptr + 4 * iphdr->ip_hl);
			get_res(thread, UDP_P, inet_ntoa(iphdr->ip_src), NULL, udphdr, NULL);
		break ;
		case IPPROTO_ICMP:
			icmphdr = (struct icmp *)(packetptr + hdr_len1);
			struct ip	*ip;

			ip = (struct ip *)(packetptr + hdr_len1 + 8);
			hdr_len2 = ip->ip_hl << 2;
			tcphdr = (struct tcphdr *)(packetptr + hdr_len1 + 8 + hdr_len2);
			get_res(thread, ICMP_P, inet_ntoa(ip->ip_dst), tcphdr, NULL, icmphdr);
		break ;
	}
}
