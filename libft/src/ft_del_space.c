/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_del_space.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/06/29 15:33:34 by rcherik           #+#    #+#             */
/*   Updated: 2015/06/29 15:57:46 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_del_space(char *s)
{
	char	*ret;
	int		i;
	int		len;

	i = 0;
	len = 0;
	while (s[i])
	{
		if (s[i] != ' ' && s[i] != '\t')
			len++;
		i++;
	}
	ret = ft_strnew(len);
	i = 0;
	len = 0;
	while (s[i])
	{
		if (s[i] != ' ' && s[i] != '\t')
		{
			ret[len] = s[i];
			len++;
		}
		i++;
	}
	return (ret);
}
