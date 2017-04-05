/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_print_red.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/06/29 14:02:00 by rcherik           #+#    #+#             */
/*   Updated: 2015/06/29 14:02:01 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>

void		ft_print_red(char *s)
{
	while (*s)
	{
		write(2, "\033[31m", 5);
		write(2, s++, 1);
		write(2, "\033[0m", 4);
	}
}