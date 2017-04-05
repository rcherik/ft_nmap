#include "ft_nmap.h"

static char	*get_hostname(char *ip)
{
	t_host	*tmp;

	tmp = nm->hosts;
	while (tmp)
	{
		if (!ft_strcmp(tmp->ip, ip))
			return (tmp->host);
		tmp = tmp->next;
	}
	return (ip);
}

static void	print_res_line(t_nmap *nm)
{
		int		i;
		
		printf("Port\tService Name");
		for (i = 0; i < 12; i++)
			printf("%c", ' ');
		printf("Results\t\t\tConclusion\n");
		for (i = 0; i < 70; i++)
			printf("%c", '-');
		printf("\n");
}

static char	*get_service(int port, t_service *services)
{
	t_service	*tmp;

	tmp = services;
	while (tmp)
	{
			if (port == tmp->port)
					return (ft_strdup(tmp->service));
				tmp = tmp->next;
	}
	return (ft_strdup("unknown"));
}

static void	conclusions(t_nmap *nm)
{
	t_target	*tmp;
	int		scan;

	tmp = nm->targets;
	while (tmp)
	{
		scan = 0;
		while (scan < N_SCAN)
		{
			tmp->res->conc = tmp->res->scans[scan] > tmp->res->conc ? tmp->res->scans[scan] : tmp->res->conc;
			scan++;
		}
		tmp = tmp->next;
	}
}

static char	*get_scan(int scan, int *len)
{
	*len += 3;
	switch (scan)
	{
		case SYN:
			return ("SYN");
		case NUL:
			*len += 1;
			return ("NULL");
		case FIN:
			return ("FIN");
		case XMAS:
			*len += 1;
			return ("XMAS");
		case ACK:
			return ("ACK");
		case UDP:
			return ("UDP");
		case TCP:
			return ("TCP");
	}
}

static void	print_conc(t_target *t)
{
	switch (t->res->conc)
	{
		case OPEN:
			printf("%sOpen", KGRN);
		break ;
		case CLOSE:
			printf("%sClosed", KRED);
		break ;
		case UNF:
			printf("%sUnfiltered", KYEL);
		break ;
		case OPFI:
			printf("%sOpen|Filtered", KBLU);
		break ;
		case FILT:
			printf("%sFiltered", KMAG);
		break ;
	}
	printf("%s", KNRM);
}

static int	get_max_scan(t_target *t)
{
	int	i;
	int	ret;

	i = 0;
	ret = 0;
	while (i < N_SCAN)
	{
		if (t->res->scans[i] != -1)
			ret++;
		i++;
	}
	return (ret);
}

static void	print_scans(t_target *t)
{
	int	i;
	int	y;
	int	scans;
	int	len;
	int	max_scan;

	i = 0;
	scans = 0;
	len = 0;
	max_scan = get_max_scan(t);
	while (i < N_SCAN)
	{
		if (t->res->scans[i] != -1)
		{
			if ((max_scan > 4 && scans == 4 || max_scan <= 4 && scans == max_scan) && scans < max_scan)
			{
				printf("\n");
				for (y = 0; y < MAX_LEN + 12; y++)
					printf(" ");
			}
			switch (t->res->scans[i])
			{
				case OPEN:
					printf("%s", KGRN);
				break ;
				case CLOSE:
					printf("%s", KRED);
				break ;
				case UNF:
					printf("%s", KYEL);
				break ;
				case OPFI:
					printf("%s", KBLU);
				break ;
				case FILT:
					printf("%s", KMAG);
				break ;
			}
			printf("%s%s ", get_scan(i, &len), KNRM);
			scans++;
		}
		if ((max_scan > 4 && scans == 4 || max_scan <= 4 && scans == max_scan) && len > 0)
		{
			len += scans;
			for (y = 0; y < 24 - len; y++)
				printf(" ");
			print_conc(t);
			len = -42;
		}

		i++;
	}
	printf("\n");
}

static void	print_results(t_target *t, t_nmap *nm)
{
	char	*service;
	int	i;

	printf("%d\t", t->port);
	service = get_service(t->port, nm->services);
	printf("%s", service);
	for (i = 0; i < MAX_LEN - ft_strlen(service) + 4; i++)
		printf("%c", ' ');
	ft_strdel(&service);
	print_scans(t);
}

void		print_res(t_nmap *nm)
{
	int		i;
	t_target	*tmp;
	t_target	*tmp2;

	conclusions(nm);
	i = 1;
	tmp = nm->targets;
	tmp2 = nm->targets;
	printf("%sOpen %sClose %sUnfiltered %sOpen|Filtered %sFiltered%s\n", KGRN, KRED, KYEL, KBLU, KMAG, KNRM);
	while (tmp)
	{
		printf("\nIP address: %s\n", get_hostname(tmp->ip));
		printf("Open ports:\n");
		print_res_line(nm);
		while (tmp2 && !ft_strcmp(tmp2->ip, tmp->ip))
		{
			if (tmp2->res->conc == OPEN)
				print_results(tmp2, nm);
			tmp2 = tmp2->next;
		}
		if (nm->n_port * nm->n_ip <= 15 || nm->show_all || nm->show_closed)
		{
			printf("\nClosed/Filtered/Unfiltered ports:\n");
			print_res_line(nm);
		}
		while (tmp && tmp != tmp2)
		{
			if (tmp->res->conc != OPEN
				&& (nm->n_port * nm->n_ip <= 15 || nm->show_all))
				print_results(tmp, nm);
			else if (tmp->res->conc == CLOSE && nm->show_closed)
				print_results(tmp, nm);
			tmp = tmp->next;
		}
	}
}
