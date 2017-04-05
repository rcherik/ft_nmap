/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/17 16:03:43 by rcherik           #+#    #+#             */
/*   Updated: 2015/12/17 19:14:01 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	add_to_port(char ***ret, int min, int max)
{
	if (min > max)
		ft_usage();
	while (min <= max)
	{
		*ret = ft_addtab(*ret, ft_itoa(min));
		min++;
	}
}

static int	find_in_tab(char *s, t_nmap *nm)
{
	int		i;

	i = 0;
	while (i < nm->n_port)
	{
		if (nm->port[i] == ft_atoi(s))
			return (1);
		i++;
	}
	return (0);
}

static void	tab_to_int(t_nmap *nm, char **p)
{
	int		i;

	i = 0;
	nm->n_port = ft_tablen(p);
	nm->port = (int *)malloc(sizeof(int) * nm->n_port);
	ft_bzero(nm->port, sizeof(int) * nm->n_port);
	while (i < nm->n_port)
	{
		if (find_in_tab(p[i], nm))
			ft_usage();
		nm->port[i] = ft_atoi(p[i]);
		i++;
	}
	ft_free_tab(&p);
}

static void	get_port(t_nmap *nm, char *s)
{
	char		**tmp;
	char		**tmp2;
	char		**ret;
	int		i;

	ret = NULL;
	i = 0;
	if (ft_strdigit(s))
	{
		nm->port = (int *)malloc(sizeof(int));
		nm->port[0] = ft_atoi(s);
		nm->n_port = 1;
		return ;
	}
	else
	{
		tmp = ft_strsplit(s, ',');
		while (tmp[i])
		{
			if (ft_strdigit(tmp[i]))
				ret = ft_addtab(ret, tmp[i]);
			else if (ft_find_char(tmp[i], 0, '-'))
			{
				tmp2 = ft_strsplit(tmp[i], '-');
				if (ft_tablen(tmp2) != 2 || !ft_strdigit(tmp2[0]) || !ft_strdigit(tmp2[1]))
					ft_usage();
				add_to_port(&ret, ft_atoi(tmp2[0]), ft_atoi(tmp2[1]));
				ft_free_tab(&tmp2);
			}
			else
				ft_usage();
			i++;
		}
		free(tmp);
	}
	tab_to_int(nm, ret);
}

static void	get_scan(t_nmap *nm, char *s)
{
	char		**tmp;
	int		i;

	i = 0;
	nm->scan = 0;
	tmp = ft_strsplit(s, '/');
	while (tmp[i])
	{
		if (!ft_strcmp(tmp[i], "SYN") && !(nm->scan & 1))
			nm->scan += 1;
		else if (!ft_strcmp(tmp[i], "NULL") && !(nm->scan & 2))
			nm->scan += 2;
		else if (!ft_strcmp(tmp[i], "FIN") && !(nm->scan & 4))
			nm->scan += 4;
		else if (!ft_strcmp(tmp[i], "XMAS") && !(nm->scan & 8))
			nm->scan += 8;
		else if (!ft_strcmp(tmp[i], "ACK") && !(nm->scan & 16))
			nm->scan += 16;
		else if (!ft_strcmp(tmp[i], "UDP") && !(nm->scan & 32))
			nm->scan += 32;
		else if (!ft_strcmp(tmp[i], "TCP") && !(nm->scan & 64))
			nm->scan += 64;
		else
			ft_usage();
		i++;
	}
	ft_free_tab(&tmp);
}

static void	get_ips(t_nmap *nm)
{
	char			*l;
	int			fd;
	char			*tmp;
	struct sockaddr_in	dest;

	if ((fd = open(nm->file, O_RDONLY)) < 0)
		ft_error("Error: can not open file. Quitting.");
	while (get_next_line(fd, &l) > 0)
	{
		tmp = NULL;
		if (inet_pton(AF_INET, l, &dest.sin_addr) < 1)
		{
			tmp = ft_strdup(l);
			l = get_host(l);
			add_host(&nm->hosts, l, tmp);
		}
		nm->host_alive = 0;
		if (!nm->pn && !ft_is_in_tab(l, nm->tmp_ips))
			nm->tmp_ips = ft_addtab(nm->tmp_ips, l);
		else if (!ft_is_in_tab(l, nm->ips))
			nm->ips = ft_addtab(nm->ips, l);
		nm->n_ips++;
	}
	close(fd);
}

static void	get_opt(t_nmap *nm, char **argv, int *i)
{
	struct sockaddr_in	dest;

	if (!ft_strcmp(argv[*i], "--ip"))
	{
		if (nm->ip || !argv[*i + 1] || nm->file)
			ft_usage();
		nm->ip = ft_strdup(argv[*i + 1]);
		if (inet_pton(AF_INET, nm->ip, &dest.sin_addr) < 1)
			nm->ip = get_host(nm->ip);
		add_host(&nm->hosts, nm->ip, argv[*i + 1]);
		*i += 1;
		nm->host_alive = 0;
		if (!nm->pn)
			nm->tmp_ips = ft_addtab(nm->tmp_ips, nm->ip);
		else
			nm->ips = ft_addtab(nm->ips, nm->ip);
		nm->n_ips++;
	}
	else if (!ft_strcmp(argv[*i], "--help"))
		ft_usage();
	else if (!ft_strcmp(argv[*i], "--ports"))
	{
		if (!argv[*i + 1] || nm->n_port)
			ft_usage();
		get_port(nm, argv[*i + 1]);
		if (nm->n_port > 1024)
			ft_usage();
		ft_sort_int(nm->port, nm->n_port);
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--file"))
	{
		if (nm->file || !argv[*i + 1] || nm->ip)
			ft_usage();
		nm->file = argv[*i + 1];
		get_ips(nm);
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--speedup"))
	{
		if (nm->speedup || !argv[*i + 1])
			ft_usage();
		nm->speedup = ft_atoi(argv[*i + 1]);
		if (nm->speedup <= 0 || nm->speedup > 250)
			ft_usage();
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--ttl"))
	{
		if (nm->ttl || !argv[*i + 1])
			ft_usage();
		nm->ttl = ft_atoi(argv[*i + 1]);
		if (nm->ttl < 0)
			ft_usage();
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--scan"))
	{
		if (!argv[*i + 1])
				ft_usage();
			get_scan(nm, argv[*i + 1]);
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--Pn"))
		nm->pn = 1;
	else if (!ft_strcmp(argv[*i], "--spoof"))
	{
		if (nm->src_addr || !argv[*i + 1])
			ft_usage();
		nm->src_addr = ft_strdup(argv[*i + 1]);
		if (inet_pton(AF_INET, nm->src_addr, &dest.sin_addr) < 1)
			nm->src_addr = get_host(nm->src_addr);
		*i += 1;
	}
	else if (!ft_strcmp(argv[*i], "--show-all"))
		nm->show_all = 1;
	else if (!ft_strcmp(argv[*i], "--show-closed"))
		nm->show_closed = 1;
	else
		ft_usage();
}	

static void	get_pn_opt(t_nmap *nm, int argc, char **argv)
{
	int	i;

	i = 0;
	while (i < argc)
	{
		if (!ft_strcmp("--Pn", argv[i]))
			nm->pn++;
		i++;
	}
	if (nm->pn > 1)
		ft_usage();
}

void		parsing(t_nmap *nm, int argc, char **argv)
{
	int	i;

	i = 1;
	get_pn_opt(nm, argc, argv);
	while (i < argc)
	{
		get_opt(nm, argv, &i);
		i++;
	}
	if (!nm->n_port)
	{
		i = 0;
		nm->n_port = 1024;
		nm->port = (int *)malloc(sizeof(int) * 1024);
		while (i < 1024)
		{
			nm->port[i] = i + 1;
			i++;
		}
	}
	if (nm->show_all && nm->show_closed)
		ft_usage();
	if (!nm->ttl)
		nm->ttl = 64;
}
