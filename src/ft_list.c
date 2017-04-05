#include "ft_nmap.h"

static t_target	*create_target(char *ip, int port)
{
	t_target	*elem;
	int		i;

	i = 0;
	elem = (t_target *)malloc(sizeof(t_target));
	if (elem)
	{
		elem->ip = ip;
		elem->port = port;
		elem->res = (t_res *)malloc(sizeof(t_res));
		while (i < N_SCAN)
		{
			elem->res->scans[i] = -1;
			i++;
		}
		elem->res->conc = 0;
		elem->next = NULL;
	}
	else
		ft_error("Malloc error. Quitting.");
	return (elem);
}

static t_service	*create_service(int port, char *service)
{
	t_service	*elem;
	int		i;

	i = 0;
	elem = (t_service *)malloc(sizeof(t_service));
	if (elem)
	{
		elem->service = ft_strdup(service);
		elem->port = port;
		elem->next = NULL;
	}
	else
		ft_error("Malloc error. Quitting.");
	return (elem);
}

static t_host	*create_host(char *ip, char *host)
{
	t_host	*elem;

	elem = (t_host *)malloc(sizeof(t_host));
	if (elem)
	{
		elem->ip = ip;
		elem->host = host;
		elem->next = NULL;
	}
	else
		ft_error("Malloc error. Quitting.");
	return (elem);
}

void	print_targets(t_target *targets)
{
	t_target	*tmp;

	tmp = targets;
	while (tmp)
	{
		printf("target: ip = %s port = %d\n", tmp->ip);
		tmp = tmp->next;
	}
}

void	print_targets2(t_thread thread)
{
	t_target	*tmp;
	int		i;

	i = 0;
	tmp = thread.targets;
	while (i < thread.n_targets)
	{
		printf("target: ip = %s port = %d\n", tmp->ip, tmp->port);
		i++;
		tmp = tmp->next;
	}
	printf("-----\n");
}

void		add_target(t_target **targets, char *ip, int port)
{
	t_target	*elem;

	elem = create_target(ip, port);
	if (!*targets)
	{
		*targets = elem;
		return ;
	}
	elem->next = *targets;
	*targets = elem;
}

void		add_host(t_host **hosts, char *ip, char *host)
{
	t_host	*elem;

	elem = create_host(ip, host);
	if (!*hosts)
	{
		*hosts = elem;
		return ;
	}
	elem->next = *hosts;
	*hosts = elem;
}

void		add_service(t_service **services, int port, char *service)
{
	t_service	*elem;

	elem = create_service(port, service);
	if (!*services)
	{
		*services = elem;
		return ;
	}
	elem->next = *services;
	*services = elem;
}
