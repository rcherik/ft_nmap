#include "ft_nmap.h"

char	*get_src_addr(void)
{
	struct ifaddrs		*addrs;
	struct ifaddrs		*tmp;
	struct sockaddr_in	*paddr;
	char			*ret;

	ret = NULL;
	getifaddrs(&addrs);
	tmp = addrs;
	while (tmp) 
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
			paddr = (struct sockaddr_in *)tmp->ifa_addr;
		tmp = tmp->ifa_next;
	}
	ret = ft_strdup(inet_ntoa(paddr->sin_addr));
	freeifaddrs(addrs);
	return (ret);
}
