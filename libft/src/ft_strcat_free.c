#include "libft.h"

char	*ft_strcat_free(char *s1, char *s2)
{
	int	i;

	i = 0;
	while (s1[i] != '\0')
		i++;
	while (*s2 != '\0')
	{
		s1[i++] = *s2;
		s2++;
	}
	s1[i] = '\0';
	ft_strdel(&s2);
	return (s1);
}
