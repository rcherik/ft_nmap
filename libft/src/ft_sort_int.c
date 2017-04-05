void	ft_sort_int(int *tab, int n)
{
	int	c;
	int	d;
	int	tmp;
 
 	c = 0;
	while (c < n - 1)
	{
		d = 0;
		while (d < n - c - 1)
		{
			if (tab[d] < tab[d + 1])
			{
				tmp = tab[d];
				tab[d] = tab[d + 1];
				tab[d + 1] = tmp;
			}
			d++;
		}
	c++;
	}
}
