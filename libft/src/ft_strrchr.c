/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/20 16:01:50 by mdufaud           #+#    #+#             */
/*   Updated: 2014/03/14 02:55:51 by jbail            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strrchr(const char *s, int c)
{
	int		i;
	char	f;

	i = 0;
	f = (char)c;
	while (*s)
	{
		i++;
		s++;
	}
	i++;
	while (i != 0)
	{
		if (*s == f)
			return ((char *)s);
		s--;
		i--;
	}
	return (NULL);
}
