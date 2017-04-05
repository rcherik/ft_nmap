/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/02/17 14:32:19 by rcherik           #+#    #+#             */
/*   Updated: 2015/02/17 14:32:26 by rcherik          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DEBUG_H
# define DEBUG_H

# define DEBUG_FUN ft_debugfun(__func__);

void	ft_debugstr(char *s);
void	ft_debugnbr(int n);
void	ft_debugchar(char c);
void	ft_debugs(char *name, char *s);
void	ft_debugn(char *name, int n);
void	ft_debugc(char *name, char c);
void	ft_debugfun(const char *s);
void	ft_debugstrn(const char *s, int until);
#endif
