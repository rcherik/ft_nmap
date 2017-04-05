/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:12 by rcherik           #+#    #+#             */
/*   Updated: 2015/06/29 15:33:18 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_atoi(const char *str)
{
	int	is_ng;
	int	val;

	val = 0;
	is_ng = 0;
	while (*str && ft_isspace(*str))
		str++;
	if (*str && (*str == '-' || *str == '+'))
	{
		if (*str == '-')
			is_ng = 1;
		str++;
	}
	while (*str && ft_isdigit(*str))
	{
		val = (val * 10) + (*str - 48) % 10;
		str++;
	}
	if (is_ng)
		val = val * -1;
	return (val);
}
