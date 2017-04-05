/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_addtab.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:35:08 by rcherik           #+#    #+#             */
/*   Updated: 2015/06/19 16:51:34 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	**ft_addtab(char **tab, char *s)
{
	char	**ret;
	int	i;

	if (!tab)
		tab = ft_tab_new(0, 0);
	ret = (char **)malloc(sizeof(char *) * (ft_tablen(tab) + 2));
	if (!ret)
		return (NULL);
	i = 0;
	while (tab[i])
	{
		ret[i] = ft_strdup(tab[i]);
		i++;
	}
	ret[i] = ft_strdup(s);
	ret[i + 1] = 0;
	ft_free_tab(&tab);
	tab = NULL;
	return (ret);
}
