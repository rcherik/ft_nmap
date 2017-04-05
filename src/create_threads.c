#include "ft_nmap.h"

void		ft_pcap_error(char *s)
{
	printf("pcap error: %s\n", s);
	exit(1);
}

static void	filter_add_host(char *filter, char *ip)
{
	ft_strcat(filter, "(src host ");
	ft_strcat(filter, ip);
	ft_strcat(filter, " && (src");
}

static void	filter_add_port(char *filter, int port, int *flag)
{
	char	*tmp;

	if (!*flag)
		ft_strcat(filter, " port ");
	else if (*flag == 1)
		ft_strcat(filter, " || ");
	else if (*flag == 2)
		ft_strcat(filter, " || port ");
	tmp = ft_itoa(port);
	ft_strcat(filter, tmp);
	ft_strdel(&tmp);
	*flag = 1;
}

static void	filter_add_range(char *filter, int end, int start, int *flag)
{
	char	*tmp;

	if (!*flag)
		ft_strcat(filter, " portrange ");
	else if (*flag == 1)
		ft_strcat(filter, " || portrange ");
	else if (*flag == 2)
		ft_strcat(filter, " || ");
	tmp = ft_itoa(start);
	ft_strcat(filter, tmp);
	ft_strdel(&tmp);
	ft_strcat(filter, "-");
	tmp = ft_itoa(end);
	ft_strcat(filter, tmp);
	ft_strdel(&tmp);
	*flag = 2;
}

static void	range_port(t_target **tmp, int *i, int n_targets, char *curr_ip, int *start, int *end)
{
	int		curr_port;

	*start = (*tmp)->port;
	curr_port = (*tmp)->port;
	while (*i < n_targets && !ft_strcmp(curr_ip, (*tmp)->ip) && ((*tmp)->port - curr_port < 2))
	{
		curr_port = (*tmp)->port;
		(*i)++;;
		(*tmp) = (*tmp)->next;
	}
	*end = curr_port;
}

static void	filter_check_port(t_target **t, int *i, int n_targets, char *curr_ip, char *filter)
{
	int		start;
	int		end;
	int		flag;

	flag = 0;
	while (*i < n_targets && !ft_strcmp(curr_ip, (*t)->ip))
	{
		range_port(t, i, n_targets, curr_ip, &start, &end);
		if (start == end)
			filter_add_port(filter, start, &flag);
		else if (end == start + 1)
		{
			filter_add_port(filter, start, &flag);
			filter_add_port(filter, end, &flag);
		}
		else
			filter_add_range(filter, start, end, &flag);
	}
}

static char	*create_filter(t_thread *thread, int scan)
{
	t_target	*tmp;
	char		*filter;
	char		curr_ip[256];
	int		i;

	i = 0;
	filter = ft_strnew(BUFF_FILTER);
	tmp = thread->targets;
	ft_clearcat(curr_ip, tmp->ip);
	if (scan == UDP)
		ft_clearcat(filter, "icmp || (udp && ");
	else
		ft_clearcat(filter, "icmp || (tcp && ");
	filter_add_host(filter, curr_ip);
	while (i < thread->n_targets)
	{
		filter_check_port(&tmp, &i, thread->n_targets, curr_ip, filter);
		if (i < thread->n_targets && ft_strcmp(tmp->ip, curr_ip))
		{
			ft_clearcat(curr_ip, tmp->ip);
			ft_strcat(filter, ")) || ");
			filter_add_host(filter, curr_ip);
		}
	}
	ft_strcat(filter, ")))");
	return (filter);
}

static void	*scanning(void *data)
{
	char		error_buff[BUFF_SIZE];
	t_thread	*thread;
	int		wait_time;
	char		device[BUFF_SIZE];

	thread = (t_thread *)data;
	thread->count = 0;
	if (nm->threads->scan == TCP)
	{
		send_packets(thread, nm->threads->scan);
		return ;
	}
	thread->filter = thread->scan == UDP ? create_filter(thread, UDP) : create_filter(thread, TCP);
	pthread_mutex_lock(&nm->mutex);
	!ft_strcmp(thread->targets->ip, "127.0.0.1") ? ft_clearcat(device, nm->local_device) : ft_clearcat(device, nm->device);
	if (pcap_lookupnet(device, &thread->netp, &thread->maskp, thread->error_buff))
		ft_pcap_error(thread->error_buff);
	thread->addr.s_addr = thread->maskp;
	wait_time = thread->n_targets > N_PACKET ? N_PACKET * TIME_ONE : thread->n_targets * TIME_ONE;
	wait_time = wait_time < TIME_MIN ? TIME_MIN : wait_time;
	if (thread->scan == UDP)
		wait_time = TIME_UDP;
	if (!(thread->pcap = pcap_open_live(device, BUFSIZ, 0, wait_time, thread->error_buff)))
		ft_pcap_error(thread->error_buff);
	if (pcap_compile(thread->pcap, &thread->fp, thread->filter, 1, thread->netp) < 0)
		ft_pcap_error(pcap_geterr(thread->pcap));
	if (pcap_setfilter(thread->pcap, &thread->fp) < 0)
		ft_pcap_error(pcap_geterr(thread->pcap));
	pthread_mutex_unlock(&nm->mutex);
	while (thread->count < thread->n_targets)
	{
		send_packets(thread, nm->threads->scan);
		thread->ret += pcap_dispatch(thread->pcap, thread->n_targets, (pcap_handler)parse_packet, (u_char *)thread);
	}
	thread->count = 0;
	no_answer(thread);
	pcap_close(thread->pcap);
	pcap_freecode(&thread->fp);
	ft_strdel(&thread->filter);
}

void		create_threads(t_nmap *nm, int scan)
{
	int		i;

	i = 0;
	while (i < nm->speedup && i < nm->n_port)
	{
		nm->threads[i].scan = scan;
		if (pthread_create(&nm->threads[i].t, 0, scanning, &nm->threads[i]))
			ft_error("Error: pthread_create");
		i++;
	}
	i = 0;
	while (i < nm->speedup && i < nm->n_port)
	{
		pthread_join(nm->threads[i].t, 0);
		i++;
	}
}
