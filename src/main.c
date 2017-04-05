/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/17 15:56:23 by rcherik           #+#    #+#             */
/*   Updated: 2016/12/20 16:18:03 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	ft_usage(void)
{
	ft_putendl("Help Screen:\n\
		ft_nmap [OPTIONS]\n\
		--help Print this help screen\n\
		--ports <Ports> to scan (eg: 1-10 or 1,2,3 or 1,5-15) (max 1024)\n\
		--ip <IP_Addresse> to scan\n\
		--file <File name> containing IP addresses to scan,\n\
		--speedup [1-250] number of parallel threads to use\n\
		--scan SYN/NULL/FIN/XMAS/ACK/UDP/TCP\n\
		--Pn Treat all hosts as online -- skip host discovery\n\
		--show-closed Show closed ports\n\
		--show-all Show all results\n\
		--ttl <val>: Set IP time-to-live field\n\
		--spoof <IP_Address> Spoof source address");
	exit(-1);
}

void	spoof_usage(void)
{
	printf("%sWARNING: If --spoof is being used to fake your source address, you also have to use --Pn.\nQUITTING!\n%s", KRED, KNRM);
	exit(-1);
}

void	ft_error(char *s)
{
	ft_print_red(s);
	write(1, "\n", 1);
	exit(1);
}

static void	print_time(t_nmap *nm)
{
	struct timeval	now;

	gettimeofday(&now, NULL);
	printf("\nft_nmap done: %d IP address (%d host%sup) ", nm->n_ips, nm->n_ip, nm->n_ip > 1 ? "s " : " ");
	printf("scanned in %ld.%ld seconds\n", 
	now.tv_sec - nm->start.tv_sec, (now.tv_usec - nm->start.tv_usec) < 0 ? (now.tv_usec - nm->start.tv_usec) / -1000 : (now.tv_usec - nm->start.tv_usec) / 1000);
}

static void	check_ips(t_nmap *nm)
{
	int	i;

	i = 0;
	if (!nm->src_addr)
		nm->src_addr = get_src_addr();
	else
		spoof_usage();
	if (!nm->src_addr)
		ft_error("Error: can't get source address.");
	while (nm->tmp_ips[i])
	{
		nm->host_alive = 0;
		if (host_discovery(nm->tmp_ips[i]) && nm->host_alive)
			nm->ips = ft_addtab(nm->ips, nm->tmp_ips[i]);
		else
			printf("%sAddress: %s is not responding.%s\n", KRED, nm->tmp_ips[i], KNRM);
		i++;
	}
	ft_free_tab(&nm->tmp_ips);
}

int		main(int argc, char **argv)
{
	pthread_t	listen;
	t_target	t;

	if (argc < 2)
		ft_usage();
	if (getuid())
		ft_error("Error: root privileges needed.");
	nm = (t_nmap *)malloc(sizeof(t_nmap));
	ft_bzero(nm, sizeof(t_nmap));
	nm->scan = 63;
	parsing(nm, argc, argv);
	if (!nm->n_ips)
		ft_usage();
	if (!nm->pn)
		check_ips(nm);
	if (!nm->src_addr)
		nm->src_addr = get_src_addr();
	if (!nm->ip && !nm->file)
		ft_usage();
	ft_config(nm);
	pthread_mutex_init(&nm->mutex, NULL);
	ft_dispatch(nm);
	print_res(nm);
	print_time(nm);
	return (0);
}
