#include "ft_nmap.h"

unsigned short	csum(unsigned short *ptr, int nbytes)
{
    register long	sum;
    unsigned short	oddbyte;
    register short	answer;
 
    sum =   0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

static void	fill_iph(t_nmap *nm, struct iphdr *iph, char *ip)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(ID_TCP);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(nm->src_addr);
	iph->daddr = inet_addr(ip);
}

static void	fill_tcph(struct tcphdr *tcph, int port, int scan)
{
	tcph->source = htons(SRC_PORT);
	tcph->dest = htons(port);
	tcph->seq = htons(45);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = scan == FIN || scan == XMAS ? 1 : 0;
	tcph->syn = scan == SYN ? 1 : 0;
	tcph->rst = 0;
	tcph->psh = scan == XMAS ? 1 : 0;
	tcph->ack = scan == ACK ? 1 : 0;
	tcph->urg = scan == XMAS ? 1 : 0;
	tcph->window = htons(14600);
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

static void	fill_psh(t_nmap *nm, struct pseudo_header *psh, struct tcphdr *tcph, char *ip)
{
	psh->src = inet_addr(nm->src_addr);
	psh->dest = inet_addr(ip);
	psh->protocol = IPPROTO_TCP;
	psh->placeholder = 0;
	psh->tcp_length = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh->tcp, tcph, sizeof(struct tcphdr));
	tcph->check = csum((unsigned short*)psh , sizeof(struct pseudo_header));
}

static void	send_tcp(t_nmap *nm, int scan, int port, char *ip, int sock)
{
	int			sent;
	char			*datagram;
	struct iphdr		*iph;
	struct tcphdr		*tcph;
	struct sockaddr_in	dest;
    	struct pseudo_header	psh;

	datagram = (char *)malloc(4096);
	ft_bzero(datagram, 4096);
	ft_bzero(&dest, sizeof(dest));
	iph = (struct iphdr *)datagram;
	tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
	inet_pton(AF_INET, ip, &dest.sin_addr);
	fill_iph(nm, iph, ip);
	iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
	fill_tcph(tcph, port, scan);
	dest.sin_family = AF_INET;
	fill_psh(nm, &psh, tcph, ip);
	if ((sent = sendto(sock, datagram, sizeof(struct iphdr)
		+ sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest))) < 0)
		ft_error("Error: sendto.");
	ft_strdel(&datagram);
}

static void	send_connect(t_nmap *nm, int port, char *ip, int sock, int *ret)
{
	struct sockaddr_in	dest;
	int			sock_tcp;

	if ((sock_tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		ft_error("Error: tcp_sock.");
	inet_pton(AF_INET, ip, &(dest.sin_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	if (connect(sock_tcp, (const struct sockaddr *)&dest, sizeof(dest)))
		*ret = FILT;
	else
		*ret = OPEN;
	close(sock_tcp);
}

void		send_packet(t_nmap *nm, int scan, int port, char *ip, int sock, int *ret)
{
	if (scan == UDP)
		send_udp(nm, scan, port, ip, sock);
	else if (scan == TCP)
		send_connect(nm, port, ip, sock, ret);
	else
		send_tcp(nm, scan, port, ip, sock);
}

void		send_packets(t_thread *thread, int scan)
{
	int		send_sock;
	int		opt;
	int		i;
	int		n_packet;
	t_target	*tmp;

	i = 0;
	tmp = thread->targets;
	while (i < thread->count)
	{
		tmp = tmp->next;
		i++;
	}
	opt = 1;
	if ((send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
		ft_error("Error: send_sock.");
	if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
		ft_error("Error: send_sock.");
	i = 0;
	if (scan == UDP)
		n_packet = 1;
	else if (scan == TCP)
		n_packet = thread->n_targets;
	else
		n_packet = N_PACKET;
	while (tmp && i < n_packet && thread->count < thread->n_targets)
	{
		send_packet(nm, scan, tmp->port, tmp->ip, scan == TCP ? 0 : send_sock, &tmp->res->scans[TCP]);
		i++;
		thread->count++;
		tmp = tmp->next;
	}
}
