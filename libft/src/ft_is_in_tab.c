#include "libft.h"

int	ft_is_in_tab(char *s, char **tab)
{
	int	i;

	i = 0;
	while (i < ft_tablen(tab))
	{
		if (!ft_strcmp(tab[i], s))
			return (1);
		i++;
	}
	return (0);
}
