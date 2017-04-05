# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: rcherik <rcherik@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2015/02/17 14:31:01 by rcherik           #+#    #+#              #
#    Updated: 2015/12/17 18:54:50 by rcherik          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap
CFLAGS = gcc
OFLAGS = -I libft/includes/. -I ./includes/.
LFLAGS = -L libft -lft -L /usr/lib -lpcap -lpthread
LIB = libft/libft.a
MKLIB = make -C libft
PATH_SRC = src
PATH_OBJ = obj
SRC = main.c\
	  parsing.c\
	  ft_dispatch.c\
	  host_discovery.c\
	  config.c\
	  send_packet.c\
	  ft_list.c\
	  send_udp.c\
	  get_payload.c\
	  get_host.c\
	  get_src_addr.c\
	  get_next_line.c\
	  create_threads.c\
	  ft_sniffing.c\
	  print_res.c\

OBJ = $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRC))

all : $(NAME)

$(PATH_OBJ)/%.o : $(addprefix $(PATH_SRC)/, %.c)
	@mkdir -p $(PATH_OBJ)
	@$(CFLAGS) $(OFLAGS) -o $@ -c $^

$(LIB) :
	@$(MKLIB)

$(NAME) : $(LIB) $(OBJ)
	@$(CFLAGS) -o $(NAME) $(OBJ) $(LFLAGS)

lib :
	@$(MKLIB)
	@make

clean :
	@$(MKLIB) clean
	@rm -f $(OBJ)
	@rm -rf $(PATH_OBJ)

fclean : clean
	@$(MKLIB) fclean
	@rm -f $(NAME)

re : fclean all

.PHONY : fclean re clean all
