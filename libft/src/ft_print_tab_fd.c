/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_print_tab_fd.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/07 17:25:16 by mdufaud           #+#    #+#             */
/*   Updated: 2014/02/07 04:38:33 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_print_tab_fd(char **tab, int fd)
{
	int	i;

	i = 0;
	if (!tab || !tab[0] || !tab[0][0])
	{
		ft_putstr_fd("Tab -> ", fd);
		ft_putendl_fd(NULL, fd);
		return ;
	}
	while (tab[i])
	{
		ft_putstr_fd("tab[", fd);
		ft_putnbr_fd(i, fd);
		ft_putstr_fd("] ", fd);
		if (ft_tablen(tab) > 10 && i < 10)
			ft_putchar_fd(' ', fd);
		ft_putstr_fd(": ", fd);
		ft_putstr_fd("'", fd);
		ft_putstr_fd(tab[i], fd);
		ft_putendl_fd("'", fd);
		i++;
	}
}
