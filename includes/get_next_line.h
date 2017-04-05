#ifndef GET_NEXT_LINE_H
# define GET_NEXT_LINE_H
# define BUF_SIZE 4096

# include "libft.h"
# define SUB1 ft_strsub_end((*tab)->string, (*tab)->i, ((*tab)->i + c[1]) - 1)
# define SUB2 ft_strsub_end((*tab)->string, (*tab)->i, ((*tab)->i + c[1]))

typedef struct	s_line
{
	char		*string;
	int			size;
	int			i;
}				t_line;

int				get_next_line(int const fd, char **line);
#endif
