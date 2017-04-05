/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 17:28:21 by mdufaud           #+#    #+#             */
/*   Updated: 2014/03/14 02:51:56 by jbail            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

void	*ft_memchr(const void *s, int c, size_t n)
{
	const char	*str;
	char		f;

	str = s;
	f = (char)c;
	while (n-- != 0)
	{
		if (*str == f)
			return ((void *)str);
		str++;
	}
	return (NULL);
}
