#include "ft_nmap.h"

static char	*get_scan(int scan)
{
	if (nm->scan & 1)
		return ("SYN");
	if (nm->scan & 2)
		return ("NULL");
	if (nm->scan & 4)
		return ("FIN");
	if (nm->scan & 8)
		return ("XMAS");
	if (nm->scan & 16)
		return ("ACK");
	if (nm->scan & 32)
		return ("UDP");
	if (nm->scan & 64)
		return ("TCP");
	else
		return ("WTF");
}

static void	get_services(t_nmap *nm)
{
	int		fd;
	char	*l;
	char	**tab;
	char	buf[BUF_SIZE];
	char	error_buff[BUFF_SIZE];

	if ((fd = open("services", O_RDONLY)) < 0)
		return ;
 	while (get_next_line(fd, &l) > 0)
	{
		tab = ft_strsplit(l, '\t');
		add_service(&nm->services, ft_atoi(tab[1]), tab[0]);
		ft_strdel(&l);
		ft_free_tab(&tab);
	}
	close(fd);
}

static void	find_devices(t_nmap *nm)
{
	char		error_buff[BUFF_SIZE];
	pcap_if_t	*devs;
	pcap_if_t	*tmp;
	char		buf[BUFF_SIZE];

	if (pcap_findalldevs(&devs, error_buff))
		ft_pcap_error(error_buff);
	tmp = devs;
	while (devs)
	{
			while (devs->addresses)
			{
					inet_ntop(devs->addresses->addr->sa_family, &((struct sockaddr_in *)devs->addresses->addr)->sin_addr, buf, BUFF_SIZE);
					if (devs->addresses->addr->sa_family == AF_INET && buf && !ft_strcmp("127.0.0.1", buf))
							nm->local_device = ft_strdup(devs->name);
					else if (devs->addresses->addr->sa_family == AF_INET && buf && ft_strcmp("127.0.0.1", buf))
							nm->device = ft_strdup(devs->name);
					devs->addresses = devs->addresses->next;
			}
			devs = devs->next;
	}
	pcap_freealldevs(tmp);
	if (!nm->device || !nm->local_device)
		ft_error("Error gettint devices. Quitting.");
}

void		ft_config(t_nmap *nm)
{
	ft_print_green("Scan configurations:\n");
	if (!nm->file)
	{
		ft_print_green("Target Ip-Addresss : ");
		ft_putendl(nm->ip);
	}
	else
	{
		ft_print_green("file : ");
		ft_putendl(nm->file);
	}
	nm->n_ip = ft_tablen(nm->ips);
	printf("%sNo of IP :%s %d\n%sNo of Ports to scan : %s%d\n%sScans to be performed : %s%s\n%sNo of threads : %s%d\n", KGRN, KNRM, nm->n_ip, KGRN, KNRM, nm->n_port * nm->n_ip, KGRN, KNRM, nm->scan == 63 ? "SYN NULL FIN XMAS ACK UDP" : get_scan(nm->scan), KGRN, KNRM, nm->speedup);
	if (!nm->n_ip)
		ft_error("No address responding. Quitting.");
	get_services(nm);
	find_devices(nm);
}
