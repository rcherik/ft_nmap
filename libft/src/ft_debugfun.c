/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_debugfun.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:30 by rcherik           #+#    #+#             */
/*   Updated: 2015/02/17 14:35:51 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_debugfun(const char *s)
{
	static int	i = 0;

	ft_putstr_fd("Entering '", 2);
	ft_putstr_fd(s, 2);
	ft_putstr_fd("' step [", 2);
	ft_putnbr_fd(i, 2);
	ft_putstr_fd("]", 2);
	ft_putchar_fd('\n', 2);
	i++;
}
