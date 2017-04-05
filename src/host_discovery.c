#include "ft_nmap.h"

static unsigned short	cksum(unsigned short *addr, int len)
{
	unsigned short	result;
	unsigned int	sum;

	sum = 0;
	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1)
	sum += *(unsigned char*) addr;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return (result);
}

static void		set_icmp(struct icmp *icmp, int type)
{
	icmp->icmp_type = type;
	icmp->icmp_code = 0;
	icmp->icmp_id = getpid();
	icmp->icmp_seq = 42;
	icmp->icmp_cksum = 0;
}

static void		send_icmp(char *ip, int sock, int type)
{
	struct icmp		*icmp;
	char			send_buf[BUFF_SIZE];
	char			tmp[BUFF_SIZE];
	struct timeval		*time_send;
	struct timeval		time_recv;
	struct sockaddr_in	send;

	send.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &send.sin_addr);
	icmp = (struct icmp *)send_buf;
	set_icmp(icmp, type);
	time_send = (struct timeval *)icmp->icmp_data;
	gettimeofday(time_send, NULL);
	icmp->icmp_cksum = cksum((unsigned short *)icmp, ICMP_LEN);
	if (sendto(sock, send_buf, ICMP_LEN, 0, (struct sockaddr *)&send, sizeof(send)) < 0)
		ft_error("Error: sendto failed");
}

static void	parse_packet2(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
	struct ip	*iphdr;
	struct icmp	*icmphdr;
	struct tcphdr	*tcphdr;
	int		hdr_len1;
	int		*type;
	
 	type = (int *)user;
	packetptr += 14;
	iphdr = (struct ip *)packetptr;
	hdr_len1 = iphdr->ip_hl << 2;
	if (iphdr->ip_p == IPPROTO_TCP)
	{
		tcphdr = (struct tcphdr*)(packetptr + 4 * iphdr->ip_hl);
		if (*type == SYN && (tcphdr->syn || tcphdr->ack && tcphdr->syn))
			nm->host_alive++;
		else if (*type == ACK && tcphdr->rst)
			nm->host_alive++;

	}
	else
	{
		icmphdr = (struct icmp *)(packetptr + hdr_len1);
		if (icmphdr->icmp_type == ICMP_ECHOREPLY || icmphdr->icmp_type == ICMP_TIMESTAMPREPLY)
			nm->host_alive++;
	}
}

static void	snif_host(char *ip, int port, int type, int sock)
{
	char				error_buff[BUFF_SIZE];
	char				filter[BUF_SIZE];
	char				*device;
	bpf_u_int32			netp;
	bpf_u_int32			maskp;
	struct bpf_program	fp;
	struct in_addr		addr;
	pcap_t				*pcap;
	int					ret;

	if (nm->host_alive)
		return ;
	ft_bzero(filter, BUF_SIZE);
	type == SYN || type == ACK ? sprintf(filter, "tcp && src host %s && src port %d", ip, port) : sprintf(filter, "icmp && src host %s", ip);
	if (!(device = pcap_lookupdev(error_buff)))
		ft_pcap_error(error_buff);
	if (!ft_strcmp(ip, "127.0.0.1"))
		device = ft_strdup("lo");
	if (pcap_lookupnet(device, &netp, &maskp, error_buff))
		ft_pcap_error(error_buff);
	addr.s_addr = maskp;
	if (!(pcap = pcap_open_live(device, BUFSIZ, 0, 300, error_buff)))
		ft_pcap_error(error_buff);
	if (pcap_compile(pcap, &fp, filter, 1, netp) < 0)
		ft_pcap_error(pcap_geterr(pcap));
	if (pcap_setfilter(pcap, &fp) < 0)
		ft_pcap_error(pcap_geterr(pcap));
	type == SYN || type == ACK ? send_packet(nm, type, port, ip, sock, NULL) : send_icmp(ip, sock, port);
	ret = pcap_dispatch(pcap, 1, (pcap_handler)parse_packet2, (void *)&type);
	pcap_close(pcap);
	if (!ft_strcmp(ip, "127.0.0.1"))
			ft_strdel(&device);
}

int		host_discovery(char *ip)
{
	int		sock_tcp;
	int		sock_icmp;
	int		opt;
	int		i;

	opt = 1;
	if ((sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
		ft_error("Error: socket.");
	if (setsockopt(sock_tcp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
		ft_error("Error: socket.");
	if ((sock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		ft_error("Error: socket failed.");
	snif_host(ip, ICMP_ECHO, ICMP_P, sock_icmp);
	snif_host(ip, 443, SYN, sock_tcp);
	snif_host(ip, 80, ACK, sock_tcp);
	snif_host(ip, ICMP_TIMESTAMP, ICMP_P, sock_icmp);
}
