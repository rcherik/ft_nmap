/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_debugstr.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:48 by rcherik           #+#    #+#             */
/*   Updated: 2015/02/17 14:35:51 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_debugstr(char *s)
{
	ft_putchar_fd('\"', 2);
	if (!s)
		ft_putstr_fd("(null)", 2);
	else
		ft_putstr_fd(s, 2);
	ft_putchar_fd('\"', 2);
	ft_putchar_fd('\n', 2);
}
