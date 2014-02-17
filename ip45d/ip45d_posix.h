


/* initialize output socket */
int init_sock_posix();


/* POSIX only : daemonize process */
void daemonize_posix(void);

/* POSIX only: alloc tun device */
int tun_alloc_posix(char *dev);

/* POSIX only: main loop */
int main_loop_posix(int verbose_opt);


