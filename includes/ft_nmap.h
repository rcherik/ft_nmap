/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/17 15:54:16 by rcherik           #+#    #+#             */
/*   Updated: 2015/12/17 18:58:45 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "libft.h" 
# include "get_next_line.h"
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <pcap.h>
# include <ifaddrs.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <pthread.h>
# include <signal.h>
# include <ifaddrs.h>
# include <poll.h>
# include <fcntl.h>
# include <errno.h>

# define ICMP_LEN 64
# define SRC_PORT 30035
# define BUFF_SIZE 1024
# define BUFF_FILTER 100000
# define ICMP_LEN 64
# define MAX_LEN 20

# define ID_TCP 54321
# define ID_UDP 12345

# define ICMP_P 0
# define UDP_P 1
# define TCP_P 2

# define SYN 0
# define NUL 1
# define FIN 2
# define XMAS 3
# define ACK 4
# define UDP 5
# define TCP 6
# define N_SCAN 7

# define TIME_MIN 150
# define TIME_UDP 1000
# define TIME_ONE 25
# define N_PACKET 5

# define OPEN 5
# define CLOSE 4
# define UNF 3
# define OPFI 2
# define FILT 1

# define KNRM "\x1B[0m"
# define KRED "\x1B[31m"
# define KGRN "\x1B[32m"
# define KYEL "\x1B[33m"
# define KBLU "\x1B[34m"
# define KMAG "\x1B[35m"
# define KCYN "\x1B[36m"
# define KWHT "\x1B[37m"

struct				pseudo_header
{
	unsigned int		src;
	unsigned int		dest;
	unsigned char		placeholder;
	unsigned char		protocol;
	unsigned short		tcp_length;
	struct tcphdr		tcp;
}; 

typedef struct			s_res
{
	int			scans[N_SCAN];
	int			conc;
}				t_res;

typedef struct			s_target
{
	char			*ip;
	int			port;
	t_res			*res;
	struct s_target		*next;
}				t_target;

typedef struct			s_host
{
	char			*ip;
	char			*host;
	struct s_host		*next;
}				t_host;

typedef struct			s_service
{
	int			port;
	char			*service;
	struct s_service	*next;
}				t_service;

typedef struct			s_thread
{
	pthread_t		t;
	int			scan;
	int			n_targets;
	int			ret;
	int			count;
	char			*device;
	char			error_buff[BUFF_SIZE];
	bpf_u_int32		netp;
	bpf_u_int32		maskp;
	struct in_addr		addr;
	pcap_t			*pcap;
	struct bpf_program	fp;
	char			*filter;
	t_target		*targets;
}				t_thread;

struct				pseudo_udp
{
	u_int32_t		src;
	u_int32_t		dest;
	u_int8_t		placeholder;
	u_int8_t		protocol;
	u_int16_t 		udp_length;
};

typedef struct			s_payload
{
	char			*payload;
	int			len;
}				t_payload;

typedef struct			s_nmap
{
	char			*ip;
	char			*src_addr;
	char			*file;
	char			**ips;
	t_host			*hosts;
	int			*port;
	int			n_port;
	int			n_ip;
	int			speedup;
	int			scan;
	int			targets_per_thread;
	int			pn;
	int			host_alive;
	struct timeval		start;
	t_target		*targets;
	t_thread		*threads;
	pthread_mutex_t		mutex;
	int			curr_thread;
	int			n_ips;
	int			ttl;
	char			**tmp_ips;
	int			show_all;
	int			show_closed;
	t_service		*services;
	char			*device;
	char			*local_device;
}				t_nmap;

t_nmap		*nm;

void		ft_pcap_error(char *s);
void		create_threads(t_nmap *nmap, int scan);
void		print_targets(t_target *targets);
void		print_targets2(t_thread thread);
void		ft_dispatch(t_nmap *nm);
void		parsing(t_nmap *nm, int argc, char **argv);
void		ft_usage(void);
void		tcp(t_nmap *nm);
void		ft_error(char *s);
void		ft_config(t_nmap *nm);
void		ft_sniffing(t_thread *thread);
void		send_packet(t_nmap *nm, int scan, int port, char *ip, int sock, int *ret);
void		send_packets(t_thread *thread, int scan);
void		send_udp(t_nmap *nm, int scan, int port, char *ip, int sock);
t_payload	*get_payload(int port);
char		*get_host(char *ip);
char		*get_src_addr(void);
void		parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void		print_res(t_nmap *nm);
void		no_answer(t_thread *t);
int		host_discovery(char *ip);
void		add_host(t_host **hosts, char *ip, char *host);
void		add_service(t_service **services, int port, char *service);
void		add_target(t_target **targets, char *ip, int port);
unsigned short	csum(unsigned short *ptr, int nbytes);

#endif
