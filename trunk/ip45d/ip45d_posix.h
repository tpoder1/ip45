/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modfied under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/



/* initialize output socket */
int init_sock_posix();


/* POSIX only : daemonize process */
void daemonize_posix(void);

/* POSIX only: alloc tun device */
int tun_alloc_posix(char *dev);

/* POSIX only: main loop */
int main_loop_posix(int verbose_opt);


