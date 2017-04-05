#include "ft_nmap.h"

static void	fill_iph(t_nmap *nm, struct iphdr *iph, struct sockaddr_in dest, int len, char *ip)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
	iph->id = htons(ID_UDP);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = inet_addr(nm->src_addr);
	iph->daddr = inet_addr(ip);
}

static void	fill_udp(int port, struct udphdr *udph, int len)
{
	udph->source = htons(SRC_PORT);
	udph->dest = htons(port);
	udph->len = htons(8 + len);
	udph->check = 0;
}

static void	fill_psh(t_nmap *nm, struct pseudo_udp *psh, int len, char *ip)
{
	psh->src = inet_addr(nm->src_addr);
	psh->dest = inet_addr(ip);
	psh->protocol = IPPROTO_UDP;
	psh->placeholder = 0;
	psh->udp_length = htons(sizeof(struct udphdr) + len);
}

void		send_udp(t_nmap *nm, int scan, int port, char *ip, int sock)
{
	struct sockaddr_in		dest;
	struct iphdr			*iph;
	struct udphdr			*udph;
	struct pseudo_udp		psh;
	int				size;
	int				sent;
	char				datagram[4096];
	char				*pseudogram;
	char				*data;
	t_payload			*payload;

	ft_bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	inet_pton(AF_INET, ip, &dest.sin_addr);
	if (!ip)
		ft_error("Error: bad address.");
	ft_bzero(datagram, 4096);
	iph = (struct iphdr *)datagram;
	udph = (struct udphdr *)(datagram + sizeof(struct ip));
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	payload = get_payload(port);
	ft_memcpy(data, payload->payload, payload->len);
	fill_iph(nm, iph, dest, payload->len, ip);
	iph->check = csum((unsigned short *)datagram, iph->tot_len);
	fill_udp(port, udph, payload->len);
	fill_psh(nm, &psh, payload->len, ip);
	size = sizeof(struct pseudo_udp) + sizeof(struct udphdr) + payload->len;
	pseudogram = malloc(size);
	ft_memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_udp));
	ft_memcpy(pseudogram + sizeof(struct pseudo_udp), udph, sizeof(struct udphdr) + payload->len);
	udph->check = csum((unsigned short *)pseudogram, size);
	if ((sent = sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest))) < 0)
		ft_error("sendto failed");
	ft_strdel(&pseudogram);
	ft_strdel(&payload->payload);
	free(payload);
}
