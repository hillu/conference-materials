#define _GNU_SOURCE
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

           struct linux_dirent64 {
               ino64_t        d_ino;    /* 64-bit inode number */
               off64_t        d_off;    /* Not an offset; see getdents() */
               unsigned short d_reclen; /* Size of this dirent */
               unsigned char  d_type;   /* File type */
               char           d_name[]; /* Filename (null-terminated) */
           };


int main() {
  int fd = open(".", O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  char buf[65536];
  int sz = getdents64(fd, buf, sizeof(buf));
  if (sz < 0) {
    perror("getdents64");
    return 1;
  }
  write(1, buf, sz);
  return 0;
}
