#include "libft.h"

void	ft_clearcat(char *s1, const char *s2)
{
	ft_bzero(s1, ft_strlen(s1));
	ft_strcat(s1, s2);
}
