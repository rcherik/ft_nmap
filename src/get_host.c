#include "ft_nmap.h"

static void		set_hints(struct addrinfo *hints)
{
	ft_bzero(hints, sizeof(struct addrinfo));
	hints->ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
	hints->ai_socktype = 0;
	hints->ai_protocol = 0;          /* Any protocol */
	hints->ai_canonname = NULL;
	hints->ai_addr = NULL;
	hints->ai_next = NULL;
	hints->ai_flags = AI_CANONNAME;
}

char		*get_host(char *ip)
{
	struct addrinfo		hints;
	struct addrinfo		*ret;
	struct addrinfo		*ret_free;
	struct in_addr		tmp;
	char			buf[BUFF_SIZE];
	char			*s;

	if (!(inet_pton(AF_INET, ip, &tmp)))
	{
		set_hints(&hints);
		if (getaddrinfo(ip, NULL, &hints, &ret))
			ft_error(ft_strjoin("Error: unknown host ", ip));
		ret_free = ret;
		while (ret)
		{
			if (ret->ai_family == AF_INET)
			{
				ft_strdel(&ip);
				s = ft_strdup(inet_ntop(ret->ai_family, &((struct sockaddr_in *)ret->ai_addr)->sin_addr, buf, BUFF_SIZE));
				freeaddrinfo(ret_free);
				return(s);
			}
			ret = ret->ai_next;
		}
	}
	freeaddrinfo(ret_free);
	return (NULL);
}


