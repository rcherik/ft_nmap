/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_debugc.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:24 by rcherik           #+#    #+#             */
/*   Updated: 2015/02/17 14:35:51 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_debugc(char *name, char c)
{
	ft_putstr_fd(name, 2);
	ft_putstr_fd(" : ", 2);
	ft_putchar_fd(c, 2);
	ft_putchar_fd('\n', 2);
}
