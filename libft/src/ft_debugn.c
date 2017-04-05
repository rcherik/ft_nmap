/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_debugn.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:34 by rcherik           #+#    #+#             */
/*   Updated: 2015/02/17 14:35:51 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "debug.h"

void	ft_debugn(char *name, int n)
{
	if (n > 2147483647)
	{
		ft_putstr_fd("Careful, the number '", 2);
		ft_putstr_fd(name, 2);
		ft_putendl_fd("' is higher than int", 2);
		return ;
	}
	if (n < -2147483647)
	{
		ft_putstr_fd("Careful, the number '", 2);
		ft_putstr_fd(name, 2);
		ft_putendl_fd("' is lower than int", 2);
		return ;
	}
	ft_putstr_fd(name, 2);
	ft_putstr_fd(" : ", 2);
	ft_debugnbr(n);
}
