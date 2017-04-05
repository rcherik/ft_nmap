#include "ft_nmap.h"

static void	dispatch_threads(t_nmap *nm)
{
	int			i;
	int			x;
	int			y;
	int			q;
	t_target	*tmp;

	q = 0;
	i = 0;
	x = 0;
	tmp = nm->targets;
	if (!((nm->n_ip * nm->n_port) % nm->speedup))
		nm->targets_per_thread = (nm->n_ip * nm->n_port) / nm->speedup;
	else
	{
		q = (nm->n_ip * nm->n_port) % nm->speedup;
		nm->targets_per_thread = ((nm->n_ip * nm->n_port) - q) / nm->speedup;
	}
	while (i < nm->speedup && tmp)
	{
		nm->threads[x].targets = tmp;
		y = 0;
		if (q > 0)
		{
			nm->threads[x].n_targets = nm->targets_per_thread + 1;
			while (y < nm->targets_per_thread + 1)
			{
				tmp = tmp->next;
				y++;
			}
			q--;
		}
		else
		{
			nm->threads[x].n_targets = nm->targets_per_thread;
			while (y < nm->targets_per_thread)
			{
				tmp = tmp->next;
				y++;
			}
		}
		nm->threads[x].scan = nm->scan;
		x++;
		i++;
	}
}

static void	*ft_timer(void *data)
{
	pthread_mutex_t	*mutex;

	mutex = (pthread_mutex_t *)data;
	while (pthread_mutex_trylock(mutex))
	{
		ft_print_green(".");
		sleep(1);
	}
	write(1, "\n", 1);
	pthread_exit(NULL);
}

static void	launch_threads(t_nmap *nm)
{
	pthread_t	timer;
	pthread_mutex_t	mutex;

	gettimeofday(&nm->start, NULL);
	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_lock(&mutex);
	if (pthread_create(&timer, 0, ft_timer, &mutex))
		ft_error("Error: pthread_create");
	if (nm->scan & 1)
		create_threads(nm, SYN);
	if (nm->scan & 2)
		create_threads(nm, NUL);
	if (nm->scan & 4)
		create_threads(nm, FIN);
	if (nm->scan & 8)
		create_threads(nm, XMAS);
	if (nm->scan & 16)
		create_threads(nm, ACK);
	if (nm->scan & 32)
		create_threads(nm, UDP);
	if (nm->scan & 64)
		create_threads(nm, TCP);
	pthread_mutex_unlock(&mutex);
	pthread_join(timer, 0);
}

void		ft_dispatch(t_nmap *nm)
{
	int		x;
	int		y;

	x = 0;
	while (nm->ips[x])
	{
		y = 0;
		while (y < nm->n_port)
		{
			add_target(&nm->targets, nm->ips[x], nm->port[y]);
			y++;
		}
		x++;
	}
	if (!nm->speedup)
	{
		nm->speedup = 1;
		if ((nm->threads = (t_thread *)malloc(sizeof(t_thread))) == NULL)
			ft_error("malloc error. Quitting.");
	}
	else
	{
		if ((nm->threads = (t_thread *)malloc(sizeof(t_thread) * nm->speedup)) == NULL)
			ft_error("malloc error. Quitting.");
	}
	dispatch_threads(nm);
	launch_threads(nm);
}
