#include "get_next_line.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>

static int		get_next_read(t_line **tab, int const fd)
{
	char	*buf;
	int		ret;
	char	*tmp;

	if (!(buf = (char *)malloc(BUF_SIZE + 1)))
		return (-1);
	if ((ret = read(fd, buf, BUF_SIZE)) > 0)
		buf[ret] = '\0';
	if (ret == -1 || ret == 0)
	{
		free(buf);
		return (ret);
	}
	tmp = (*tab)->string;
	(*tab)->string = ft_strjoin((*tab)->string, buf);
	ft_strdel(&tmp);
	ft_strdel(&buf);
	(*tab)->size += ret;
	return (1);
}

static int		gnl_free(t_line **tab_free, char **free_str, int flag)
{
	if (*free_str)
		ft_strdel(free_str);
	if (tab_free && *tab_free)
	{
		free(*tab_free);
		*tab_free = NULL;
	}
	if (flag)
		return (1);
	return (0);
}

static int		ft_read(t_line **tab, int const fd)
{
	char	*buf;
	ssize_t	ret;

	if (!(buf = (char *)malloc(BUF_SIZE + 1)))
		return (-1);
	if ((ret = read(fd, buf, BUF_SIZE)) > 0)
		buf[ret] = '\0';
	if (ret == 0 || ret == -1)
	{
		ft_strdel(&buf);
		return (ret);
	}
	if (!(*tab = (t_line *)malloc(sizeof(t_line))))
	{
		ft_strdel(&buf);
		return (-1);
	}
	(*tab)->string = buf;
	(*tab)->i = 0;
	(*tab)->size = ret;
	return (1);
}

static int		ft_split(t_line **tab, char **line, int const fd)
{
	int		c[2];
	char	*tmp;

	c[0] = 1;
	if (!(*tab))
		return (0);
	while (!(c[1] = ft_find_char((*tab)->string, (*tab)->i, '\n')) && c[0] != 0)
	{
		if ((c[0] = get_next_read(tab, fd)) == -1)
			return (gnl_free(tab, &((*tab)->string), 0));
	}
	if (!(c[1]))
	{
		c[1] = ft_strlen((*tab)->string + (*tab)->i);
		*line = ((*tab)->string[(*tab)->i + c[1] - 1] == '\n') ? SUB1 : SUB2;
		return (gnl_free(tab, &((*tab)->string), 1));
	}
	*line = ((*tab)->string[(*tab)->i + c[1] - 1] == '\n') ? SUB1 : SUB2;
	(*tab)->i += c[1];
	tmp = (*tab)->string;
	(*tab)->string = ft_strsub_end((*tab)->string, (*tab)->i, (*tab)->size);
	(*tab)->size = (*tab)->size - (*tab)->i;
	(*tab)->i = 0;
	free(tmp);
	return (1);
}

int				get_next_line(int const fd, char **line)
{
	static void	*first = NULL;
	t_line		*tab;
	int			ret;

	ret = 0;
	tab = NULL;
	if (fd < 0 || line == NULL || (*line = NULL))
		return (-1);
	tab = !first ? NULL : first;
	if (tab && tab->i < tab->size)
		ret = ft_split(&tab, line, fd);
	else
	{
		if (tab)
			gnl_free(&tab, &tab->string, 0);
		ret = ft_read(&tab, fd);
		if (ret > 0)
			ret = ft_split(&tab, line, fd);
	}
	first = tab;
	if (ret)
		return (ret);
	if (!tab || !line)
		return (0);
	return (1);
}
