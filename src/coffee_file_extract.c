/*  Forensic analysis of the Coffee File System as used in Contiki-ng
    Copyright (C) 2929  Jens-Petter Sandvik

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <getopt.h>
#include <fcntl.h>
#include <math.h>
#include <sodium.h>

//#include "ctsource.h"

#define DEFAULT_SECTOR_SIZE 0x10000
#define DEFAULT_PAGE_SIZE   0x100
#define MAX_FILENAME        1023
#define MAX_CFS_FILENAME    40
#define DEFAULT_HEADER_SIZE 26
#define DEFAULT_LOG_SIZE    0x400
#define DEFAULT_FS_START    DEFAULT_SECTOR_SIZE

#ifndef MEM_VERSIONS
#define MEM_VERSIONS 0
#endif 

void usage(char arg0[]){
  printf("Usage: %s -p <pagesize> -s <sectorsize> -l <logsize> -b <fs start> -f <filename> -v -s -d <dir> -a <hashfile>\n", arg0);
  printf("  Default pagesize: 0x%08x\n  Default sectorsize: 0x%08x\n", DEFAULT_PAGE_SIZE, DEFAULT_SECTOR_SIZE);
  printf("  Default Coffee start offset: 0x%08x\n  Default header size: 0x%08x\n",  DEFAULT_FS_START, DEFAULT_HEADER_SIZE);
  printf("  Default log size: 0x%08x\n", DEFAULT_LOG_SIZE);
  printf("  Max filename length: %d characters\n", MAX_FILENAME);
}

enum ftype {file_unprocessed = 0,
	    file_active,
	    file_active_log,
	    file_deleted,
	    file_deleted_log, 
	    file_fragment,
	    file_isolated,
	    file_zero
}; 

enum cfs_file_flags {cfs_file_valid     = 0x01,
		     cfs_file_allocated = 0x02,
		     cfs_file_obsolete  = 0x04,
		     cfs_file_modified  = 0x08,
		     cfs_file_log       = 0x10,
		     cfs_file_isolated  = 0x20};
		

struct file_ent {
  enum ftype type;
  uint16_t log_page;
  uint16_t log_records;
  uint16_t log_record_size;
  uint16_t max_pages;
  uint8_t eof_hint; /* deprecated */ 
  uint8_t flags; 
  char name[MAX_CFS_FILENAME];
  uint64_t contentlen;
};

/* File version struct */
struct filecont {
  //int sector_version; /* version within a sector, or consecutive sectors if there is an overlapping file between the sectors */
  //int pred_version; /* Predicted version */
  uint8_t active; /* Is this version active or obsolete */
  uint64_t page_anchor; /* The page number of the original page */ 
  uint64_t log_record; /* The log record number of this version. 0 for non-log*/
  uint64_t sector_number; /* Sector number of the page */
  uint8_t *content;
  struct filecont *next;
};

struct filever {
  char name[MAX_CFS_FILENAME];
  int avsize; /* Allicated entries in double pointer list */
  struct filecont **versions; /* A list of pointers to linked list of ordered versions  */
  struct filever *next;
};

struct statistics {
  uint32_t tot_pages_calculated;
  uint32_t tot_pages_processed;
  uint32_t n_active_base;
  uint32_t n_active_log;
  uint32_t n_deleted;
  uint32_t n_deleted_log;
  uint32_t n_isolated;
  uint32_t n_zero;
  uint32_t n_unknown;
}; 

uint64_t find_sector(uint64_t page, uint64_t pagesize, uint64_t sectorsize){
  return (page*pagesize)/(sectorsize);
}

int is_page_zero(char *buf, uint64_t len){
  for (uint64_t i=0; i<(uint64_t) (len/4); i++)
    if (((uint32_t *) buf)[i] != 0)
      return 0;
  for (uint64_t i=(uint64_t) (len/4); i<len; i++)
    if (buf[i] != 0)
      return 0;
  return 1; 
}

int is_sector_zero(char *buf, uint64_t sector, uint64_t npages, uint64_t pagesize){
  for (int i = 0; i<npages; i++){
    if (!is_page_zero(buf+(i*pagesize), pagesize))
      return 0;
  }
  return 1;  
}



/* Expect a pointer to the start of the file. Return length of file contents excluding the header */
uint64_t get_file_len(uint8_t *buf, uint64_t headersize, uint64_t pagesize, uint64_t blen){
  uint64_t max_alloc;

  max_alloc = buf[6] | buf[7]<<8;
  for (int i = pagesize*max_alloc-1; i>=headersize; i--){
    if (buf[i]) return i-headersize+1;
  }
  /* If here, filesize should be 0 */ 
  return 0; 
}



struct filever *findfile(struct filever *files, char *filename){
  struct filever *tmp;
  if (!files) return NULL; 
  for (tmp = files;
       tmp && strncmp(tmp->name, filename, MAX_CFS_FILENAME) != 0;
       tmp = tmp->next); /* empty body */
  return tmp; 
}

int addfile(struct filever *fileversions, uint8_t *mmfile, uint64_t page, struct file_ent *fent){
  struct filever *newfile = NULL;
  int alloclen = 10; /* Allocate space for 10 run of versions */
  struct filever *tmp;
  
  if (fileversions == NULL || !(newfile = findfile(fileversions, fent->name))){
    /* First file */
    
    newfile = malloc(sizeof(struct filever));
    if (!newfile){
      perror("malloc");
      exit(EXIT_FAILURE);
    }
    memset(newfile, 0, sizeof(struct filever));
    /* if ((newfile->name = malloc(MAX_CFS_FILENAME)) == NULL){
      perror("malloc");
      exit(EXIT_FAILURE);
      }*/ 
    strncpy(newfile->name, fent->name, MAX_CFS_FILENAME);

    if (!(newfile->versions = malloc(sizeof(struct filecont *) * alloclen))){
      perror("malloc");
      exit(EXIT_FAILURE);
    }
    memset(newfile->versions, 0, sizeof(struct filecont *) * alloclen);
    newfile->avsize = alloclen;
    
    if (!fileversions){
      fileversions = newfile;
    } else {
      if (!fileversions->next){
	if (strncmp(newfile->name, fileversions->name, MAX_CFS_FILENAME) < 0){
	  newfile->next = fileversions;
	  fileversions = newfile;
	} else {
	  fileversions->next = newfile;
	}
      }
      for (tmp = fileversions;
	   tmp->next && strncmp(newfile->name, tmp->next->name, MAX_CFS_FILENAME) < 0;
	   tmp = tmp->next);
      newfile->next = tmp->next ? tmp->next->next : NULL;
      tmp->next = newfile;
    }
  }

  /* We have a newfile, fill out contents. */
  /* Dows it belong to an existing run, or should a new run be created? */
  for (int i=0; newfile->versions[i]; i++){
    struct filecont *c; 
    c = newfile->versions[i];
    //if (file->
  }
  
  return 1;
}

uint64_t get_content_len(uint8_t buf[], uint64_t bufsize){
  uint64_t i; 
  for (i = bufsize-1; i>=0 && !buf[i]; i--);
  return i==0 && buf[0] == 0 ? 0: i+1;
}

uint8_t probable_log_file_header(uint8_t mmfile[], uint32_t size, uint32_t coffs, uint32_t file_end, uint32_t fs_start, uint32_t pagesize){
  uint16_t logrecords, logrecordsize, maxpages;
  uint8_t flags, eofhint;
  uint8_t might_be = 0;

  /* TOOD: Name should be the same as the base file */
  
  /* Log records doesnt have other log records, and they have the log record flag set */
  if (mmfile[coffs] == mmfile[coffs+1] == 0)
    might_be++;
  else
    return 0;

  maxpages = mmfile[coffs+6] | (mmfile[coffs+7] << 8);
  if (maxpages*pagesize > size)
    return 0;
  
  if (mmfile[coffs+2] == mmfile[coffs+3] == mmfile[coffs+4] == mmfile[coffs+5] == 0)  
    might_be++;
  else {
    logrecords = mmfile[coffs+2] | (mmfile[coffs+3] << 8);
    logrecordsize = mmfile[coffs+4] | (mmfile[coffs+5] << 8);

    if (logrecords*logrecordsize > maxpages)
      return 0;

    might_be++;
    
  }

  if (mmfile[8])
    might_be++;

  if (mmfile[9] & 0x10)
    might_be++;
  
  if (might_be < 4)
    return 0;
  
  return 1; 
}

uint8_t probable_file_header(uint8_t mmfile[], uint32_t size, uint32_t coffs, uint32_t file_end, uint32_t fs_start, uint32_t pagesize){
  /* Return non-zero of this might be a file header. */
  uint16_t logpage, logrecords, logrecordsize, maxpages;
  uint8_t flags, eofhint;
  uint8_t might_be = 0;

  /* 2 highest flag  bits are not set in file header, and the two lowest bits have to be set  */
  flags = mmfile[coffs+9];
  if (flags & 0xe0
      || !(flags & 0x3))
    return 0;

  /* Check the logpage */
  logpage = mmfile[coffs] | (mmfile[coffs+1] << 8);
  logrecords = mmfile[coffs+2] | (mmfile[coffs+3] << 8);
  logrecordsize = mmfile[coffs+4] | (mmfile[coffs+5] << 8);
  
  if (!logpage)
    might_be++;
  else if ((logpage * pagesize) + fs_start < size
	   && (logpage * pagesize) + fs_start > coffs
	   && probable_log_file_header(mmfile, size, (logpage*pagesize)+fs_start, file_end, fs_start, pagesize))
    might_be++;

  if (!logrecords && !logrecordsize)
    might_be++;
  
  maxpages = mmfile[coffs+6] | (mmfile[coffs+7] << 8);
  if (maxpages*pagesize > size)
    return 0;
  
  for (int i=0x11; i<=0x8800; i = i < 1){
    if (maxpages == i){
      might_be++;
      break;
    }
  }

  eofhint = mmfile[coffs+8];
  if (!eofhint)
    might_be++;
    
  if (might_be < 4)
    return 0;
  
  /* If we're here, this is probably a file header */
  return 1;
}

void printhex(uint8_t buffer[], uint32_t offset, uint32_t size){
  uint8_t npad, nlast;
  char str[80];

  nlast = size%16;
  npad = (16-nlast)%16;
  
  for (int i=0; i<size/16; i++){
    printf("%08x | ", offset+(i*16)); 
    for (int j=0; j<16; j++){
      printf("%02x ", buffer[offset+(16*i)+j]);
    }
    printf("| ");
    for (int j=0; j<16; j++){
      if (buffer[offset+(16*i)+j] >= 0x20 && buffer[offset+(16*i)+j] <= 0x7e)
	printf("%c", buffer[offset+(16*i)+j]);
      else
	printf(".");
    }
    printf(" |\n");
  }
  if (nlast){
    printf("%08x | ", offset+size-nlast);
    for (int i=0; i<nlast; i++)
      printf("%02x ", buffer[offset+size-nlast+i]);
    for (int i=nlast; i<16; i++)
      printf("   ");
    printf("| ");
    for (int i=0; i<nlast; i++)
      if (buffer[offset+size-nlast+i] >= 0x20 && buffer[offset+size-nlast+i] <= 0x7e)
	printf("%c", buffer[offset+size-nlast+i]);
      else
	printf(".");
    for (int i=nlast; i<16; i++)
      printf(" ");
    printf(" |\n");
  }
}

void fprinthash(FILE *hashf, char *filename, char *hashval){
  fprintf(hashf, "%s  %s\n", hashval, filename);
}

int byte2str(unsigned char *buf, size_t buflen, char *str, size_t strlen){
  int i;
  char decode[] = "0123456789abcdef";
  
  if (strlen < 2*buflen) return 0;

  for (i=0; i<buflen; i++){
    str[2*i]   = decode[buf[i] >> 4];
    str[2*i+1] = decode[buf[i] & 0xf];
  }

  return 1;
}

int main(int argc, char *argv[]){
  int opt;
  uint32_t pagesize, sectorsize, logsize, coffeestart, n_pages, n_sectors, n_pages_pr_sector, headersize;
  char filename[MAX_FILENAME+1], directory[MAX_FILENAME+1], savename[2*(MAX_FILENAME+1)+10], hashfile[MAX_FILENAME+1];
  uint8_t *mmfile;
  int fd;
  FILE *of, *hashf; 
  struct stat fs; 
  struct file_ent *file_list;
  uint8_t *null_sectors;
  uint32_t unprocessed, processed, n_files, n_deleted, n_logs, n_isolated, n_zero_pages, n_zero_sectors; 
  uint8_t verbose = 0, dostats = 0;
  struct filever *fileversions; /* Zero terminated array of files found on the system. One for each filename */
  struct statistics stats;
  uint32_t file_end = 0;    /* The end page for a file object */
  uint8_t isolated_run = 1; /* Set to 1 at start of sector, 0 at first non-isolated page */
  unsigned char hashval[crypto_hash_sha256_BYTES];
  char hashstr[crypto_hash_sha256_BYTES*2+1]; 

  pagesize = DEFAULT_PAGE_SIZE;
  sectorsize = DEFAULT_SECTOR_SIZE;
  headersize = DEFAULT_HEADER_SIZE;
  logsize = DEFAULT_LOG_SIZE;
  coffeestart = DEFAULT_FS_START;
  
  memset(filename, 0, MAX_FILENAME+1);
  memset(directory, 0, MAX_FILENAME+1);
  memset(hashfile, 0, MAX_FILENAME+1);
  bzero(hashval, crypto_hash_sha256_BYTES);
  bzero(hashstr, crypto_hash_sha256_BYTES*2+1);
  
  static struct option options[] = {{"pagesize", required_argument, 0, 'p'},
				    {"sectorsize", required_argument, 0, 's'},
				    {"file", required_argument, 0, 'f'},
				    {"verbose", no_argument, 0, 'v'},
				    {"directory", required_argument, 0, 'd'},
				    {"logsize", required_argument, 0, 'l'},
				    {"coffeestart", required_argument, 0, 'b'},
                                    {"stats", no_argument, 0, 't'},
				    {"hashfile", required_argument, 0, 'a'},
				    {"help", no_argument, 0, 'h'}};
  
  while ((opt = getopt_long(argc, argv, "vtp:s:f:d:b:a:?", options, NULL)) != -1) {
    switch (opt){
    case 'f':
      strncpy(filename, optarg, MAX_FILENAME);
      break;
    case 'p':
      pagesize = strtoll(optarg, NULL, 0);
      break;
    case 'c':
      sectorsize = strtoll(optarg, NULL, 0); 
      break;
    case 'd':
      strncpy(directory, optarg, MAX_FILENAME);
      break;
    case 'b':
      coffeestart = strtoll(optarg, NULL, 0);
      break;
    case 't':
      dostats++;
      break;
    case 'a':
      strncpy(hashfile, optarg, MAX_FILENAME);
      break;
    case '?':
    case 'h': 
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    case 'v':
      verbose++;
      break;
    default:
      fprintf(stderr, "Unknown option %c\n", opt);
    }
  }

  if (!filename[0]){
    fprintf(stderr, "No filename given, exiting...\n");
    exit(EXIT_FAILURE);
  }
  
  printf("File: %s\nSectorsize: 0x%08x\nPagesize: 0x%08x\nFile system start: \%08x\n", filename, sectorsize, pagesize, coffeestart);
  printf("Output directory: %s\n", directory[0] ? directory : "<None>");
  
  if (directory[0] && stat(directory, &fs) == -1) {
    if (mkdir(directory, 0700) == -1){
      perror("mkdir");
      exit(EXIT_FAILURE);
    }
  }
  
  if (sectorsize % pagesize != 0){
    fprintf(stderr, "Pagesize does not match sectorrsize, exiting...\n");
    exit(EXIT_FAILURE);
  } else 
  
  n_pages_pr_sector = sectorsize/pagesize;
  
  fd = open(filename, O_RDONLY);
  if (fd == -1){
    perror("open");
    exit(EXIT_FAILURE);
  }

  if (fstat(fd, &fs) == -1){
    perror("fstat");
    exit(EXIT_FAILURE);
  }
  
  mmfile = (uint8_t *) mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mmfile == MAP_FAILED){
    perror("mmfile");
    exit(EXIT_FAILURE);
  }

  /* if filesize doesn't match filesize, round up on npages */
  n_pages = (uint64_t)  ceil((float) (fs.st_size-coffeestart)/ (float) pagesize);
  n_sectors = (uint64_t)  ceil((float) (fs.st_size-coffeestart)/ (float) sectorsize);
  
  if ((file_list = calloc(n_pages, sizeof(struct file_ent))) == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  memset(file_list, 0, n_pages*sizeof(struct file_ent));
  
  /* if ((page_list = calloc(n_pages, sizeof(uint8_t))) == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  memset(page_list, 0, n_pages);*/ 

  if (dostats > 0) {
    bzero(&stats, sizeof(struct statistics));
    stats.tot_pages_calculated = n_pages;
  }

  /* File for storing hash values, sha-256*/
  if (hashfile[0]){
    hashf = fopen(hashfile, "w+");
    if (hashf == NULL){
      perror("fopen");
      exit(EXIT_FAILURE);
    }
    /* Hash flash */
    crypto_hash_sha256(hashval, mmfile, fs.st_size);
    byte2str(hashval, crypto_hash_sha256_BYTES, hashstr, crypto_hash_sha256_BYTES*2+1);
    fprinthash(hashf, filename, hashstr);
  }
  
  /* Find unallocated sectors */
  null_sectors = malloc(sizeof(uint8_t)*n_sectors);
  bzero(null_sectors, sizeof(uint8_t)*n_sectors);
  
  for (uint64_t i=0; i<=n_sectors; i++)
    null_sectors[i] = is_sector_zero(mmfile+coffeestart+(i*sectorsize), i, n_pages_pr_sector, pagesize);

  
  /* Go through pages and find files */ 
  for (uint32_t p=0; p<n_pages; p++){
    uint32_t coffs = coffeestart+(p*pagesize);    
    
    if (!(p%n_pages_pr_sector))
      isolated_run = 1;
    
    if ((p == 0 || p > file_end)
	&& (mmfile[coffs+9] & cfs_file_valid)
	&& (mmfile[coffs+9] & cfs_file_allocated)
	&& !(mmfile[coffs+9] & cfs_file_obsolete)
	&& !(mmfile[coffs+9] & cfs_file_isolated)){

      /* Valid file */
      if (mmfile[coffs+9] & cfs_file_log)
	file_list[p].type = file_active_log;
      else 
	file_list[p].type = file_active;

      isolated_run = 0;
      
      file_list[p].log_page = (uint16_t) mmfile[coffs] | mmfile[coffs+1]<<8;
      file_list[p].log_records = (uint16_t) mmfile[coffs+2] | mmfile[coffs+3]<<8;
      file_list[p].log_record_size = (uint16_t) mmfile[coffs+4] | mmfile[coffs+5]<<8;
      file_list[p].max_pages =  (uint16_t) mmfile[coffs+6] | mmfile[coffs+7] << 8;
      file_list[p].eof_hint = (uint8_t) mmfile[coffs+8];
      file_list[p].flags = (uint8_t) mmfile[coffs+9];
      memcpy(file_list[p].name, (char *) (mmfile+coffs+10), MAX_CFS_FILENAME);
      file_list[p].contentlen = get_file_len(mmfile+coffs, headersize, pagesize, fs.st_size-coffs);
      file_end = p+file_list[p].max_pages-1;
      // page_list[p] = 1;
      
      if (verbose > 0){
	printf("Found existing file: %s at page %d (0x%08x)\n", file_list[p].name, p, coffs);
	printf("  Log page: %04x, log records: %04x, log record size: %04x\n",
	       file_list[p].log_page, file_list[p].log_records, file_list[p].log_record_size);
	printf("  Flags: 0x%02x\n", file_list[p].flags);
	printf("  Max pages: 0x%04x, file_end: %x\n", file_list[p].max_pages, file_end);
	printf("  File length: %08lx\n", file_list[p].contentlen);
	if (verbose > 1){
	  for (int i=0; i<32; i++) printf("%02x ", (uint8_t) *(mmfile+coffs+i));
	  printf("\n"); 
	}
      }
      if (dostats){
	stats.tot_pages_processed += file_list[p].max_pages;
	if (mmfile[coffs+9] & cfs_file_log)
	  stats.n_active_log += file_list[p].max_pages;
	else
	  stats.n_active_base += file_list[p].max_pages;
      }
    } else if ((p == 0 || p > file_end)
	       && (mmfile[coffs+9] & cfs_file_valid)
	       && (mmfile[coffs+9] & cfs_file_allocated)
	       && (mmfile[coffs+9] & cfs_file_obsolete)
	       && !(mmfile[coffs+9] & cfs_file_isolated)) {
	
      /* Deleted file */
      if (mmfile[coffs+9] & cfs_file_log)
	file_list[p].type = file_deleted_log;
      else
	file_list[p].type = file_deleted;

      isolated_run = 0;
      
      file_list[p].log_page = (uint16_t) mmfile[coffs] | mmfile[coffs+1]<<8;
      file_list[p].log_records = (uint16_t) mmfile[coffs+2] | mmfile[coffs+3]<<8;
      file_list[p].log_record_size = (uint16_t)  mmfile[coffs+4] | mmfile[coffs+5]<<8;
      file_list[p].max_pages =  (uint16_t) mmfile[coffs+6] | (mmfile[coffs+7]<<8);
      file_list[p].eof_hint = (uint8_t)  mmfile[coffs+8];
      file_list[p].flags = (uint8_t) mmfile[coffs+9];
      memcpy(file_list[p].name, (char *) (mmfile+coffs+10), MAX_CFS_FILENAME);
      file_list[p].contentlen = get_file_len(mmfile+coffs, headersize, pagesize, fs.st_size-coffs);
      file_end = p+file_list[p].max_pages-1;
      //printf("File end: %x, max_pages: %x, p: %x\n", file_end, file_list[p].max_pages, p);
      
      //page_list[p] = 1;

      if (verbose > 0) { 
	printf("Found deleted file: %s at page %d (0x%08x)\n", file_list[p].name, p, coffs);
	printf("  Log page: %04x, log records: %04x, log record size: %04x\n",
	       file_list[p].log_page, file_list[p].log_records, file_list[p].log_record_size);
	printf("  Flags: 0x%02x\n", file_list[p].flags);
	printf("  Max pages: 0x%04x, file_end: %x\n", file_list[p].max_pages, file_end);
	printf("  File length: %08lx\n", file_list[p].contentlen);
	if (verbose > 1){
	  for (int i=0; i<32; i++) printf("%02x ", (uint8_t) *(mmfile+coffs+i));
	  printf("\n"); 
	}
      }
      if (dostats){
	stats.tot_pages_processed += file_list[p].max_pages;
	if (file_list[p].flags & cfs_file_log)
	  stats.n_deleted_log += file_list[p].max_pages;
	else
	  stats.n_deleted += file_list[p].max_pages;
      }
    } else if ((!p || p > file_end)
	       && isolated_run
	       //&& (mmfile[coffs+9] & cfs_file_valid)
	       //&& (mmfile[coffs+9] & cfs_file_allocated)
	       //&& (mmfile[coffs+9] & cfs_file_obsolete)
	       && (mmfile[coffs+9] & cfs_file_isolated)){
      /* Isolated page */
      file_list[p].type = file_isolated;
      file_list[p].flags = (uint8_t) mmfile[coffs+9];
      //page_list[p] = 4;

      if (verbose > 1){
	printf("Found isolated page: %s at page %d (0x%08x)\n", file_list[p].name, p, coffs);
	printf("  Flags: 0x%02x\n", file_list[p].flags);
      }
      if (dostats){
	stats.tot_pages_processed++;
	stats.n_isolated++;
      }
      
    } else if ((!p || p > file_end)
	       && is_page_zero(mmfile+coffs, pagesize)) {
      file_list[p].type = file_zero;
      //page_list[p] = 3;
      if (dostats){
	stats.tot_pages_processed++;
	stats.n_zero++;	
      }
    } else if (p && p <= file_end && !isolated_run) {
      /* In a file */
      file_list[p].type = file_fragment;
      //printf("file_end: %x, p: %x\n", file_end, p);
      if (p == file_end)
	file_end == 0;
      //page_list[p] = 2;
    } else if (isolated_run && p <= file_end) {
      /* It might be the start of a new file. Check this */
      if (probable_file_header(mmfile, fs.st_size, coffs, file_end, coffeestart, pagesize)) {
	/* Remove rest of pages from classified pages.*/
	stats.tot_pages_processed -= file_end-p+1;
	/* TODO: Don't know which type of page the prevoius file belonged to... Should backtrack this to get the individual counts right, */
	
	/* Set file end to previous page and decrease page pointer for reclassification */
	file_end = --p;
	
	if (verbose)
	  printf("Decrease page and restart from %x\n", p);
      }			   
    } else {
      fprintf(stderr, "I shouldn't be here: page %x/%x (%x), flags: %x\n", p, file_end, coffs, mmfile[coffs+9]);
      printhex(mmfile, coffs, pagesize);
      if (dostats) {
	stats.tot_pages_processed++;
	stats.n_unknown++;
      }
    }
  }

  if (verbose>0){
    unprocessed = processed = 0;
    for (int i=0; i<n_pages; i++){
      if (file_list[i].type == file_unprocessed) unprocessed++;
      else processed++;
    }
    printf("Pages: %u, unprocessed pages: %u, processed pages: %u\n", n_pages, unprocessed, processed);
    for (int i=0; i<n_sectors; i++){
      if (null_sectors[i]) printf("Null sector %03d: 0x%08x - 0x%08x\n", i, i*sectorsize, i*sectorsize+sectorsize);
    }
  }

  
  /****************************************************************/
  /* Go through the pages and reconstruct files and file versions */ 
  /****************************************************************/

  /* Allocate enough space for all files... Max files is one for each page on the system */
  fileversions = malloc(sizeof(struct filever *)*n_pages); 
  memset(fileversions, 0, sizeof(struct filever *)*n_pages);

  
  
  for (int p=0; directory[0] && p<n_pages; p++){
    if ((file_list[p].type == file_active || file_list[p].type == file_deleted) && !(file_list[p].flags & cfs_file_modified)){
      /* Save ordinary files, live and deleted. */
      snprintf(savename, 2*MAX_FILENAME, "%s/%s_%c%04x_V0001", directory, file_list[p].name, file_list[p].type == file_active ? 'A' : 'D', p);
    
      of = fopen(savename, "w");
      if (of == NULL) {
	perror("fopen");
	exit(EXIT_FAILURE);
      }
      if (verbose > 0)
	printf("Writing: %s. %lu bytes\n", savename, file_list[p].contentlen);
      
      if (fwrite(mmfile+coffeestart+(p*pagesize)+headersize, 1, file_list[p].contentlen, of) != file_list[p].contentlen) {
	perror("fwrite");
	exit(EXIT_FAILURE);
      }
      fclose(of);

      if (hashfile[0]) {
	crypto_hash_sha256(hashval, mmfile+coffeestart+(p*pagesize)+headersize, file_list[p].contentlen);
	byte2str(hashval, crypto_hash_sha256_BYTES, hashstr, crypto_hash_sha256_BYTES*2+1);
	fprinthash(hashf, savename, hashstr);
      }

#if MEM_VERSIONS
      if (addfile(fileversions, mmfile, p, &file_list[p]) == 0) {
	fprintf(stderr, "Could not add file %s at page %ul\n", file_list[p].name, p);
      }
#endif
    
    } else if ((file_list[p].type == file_active || file_list[p].type == file_deleted) && (file_list[p].flags & cfs_file_modified)) {
      /* Modified files, has a journal. The versions are ordered within a sector, 
	 but temporarily later sectors might be physically before temporarily earlier ones..  */
      int lpage = file_list[p].log_page;
      int version, i;
      
      snprintf(savename, 2*MAX_FILENAME, "%s/%s_%c%04x_V0001", directory, file_list[p].name, file_list[p].type == file_active ? 'A' : 'D', p);
      if (verbose > 0){
	printf("Writing modified file: %s\n", savename);
      }
      of = fopen(savename, "w");
      /* Write original file as first version */ 
      if (of != NULL){
	if ((i = fwrite(mmfile+coffeestart+(p*pagesize)+headersize, file_list[p].contentlen, 1, of)) != 1){
	  printf("Could only write %d bytes out of %lu in file %s\n", i, file_list[p].contentlen, savename);
	}
	fclose(of);
	
	if (hashfile[0]){
	  crypto_hash_sha256(hashval, mmfile+coffeestart+(p*pagesize)+headersize, file_list[p].contentlen);
	  byte2str(hashval, crypto_hash_sha256_BYTES, hashstr, crypto_hash_sha256_BYTES*2+1);
	  fprinthash(hashf, savename, hashstr);
	}
	
      } else {
	perror("fopen");
	printf("Could not write file %s\n", savename);
      }
      
      if (file_list[lpage].flags & cfs_file_log) {
	/* Log file */
	/* TODO: calculate the size of log entries, number of entries properly. Placeholder is just static for now. */
	int n_logs = 4, n=0;
	uint8_t lastver[file_list[p].max_pages*pagesize-headersize];
	/* DONE: Fix bug - this does not remember earlier changes in another page */ 
	/* DONE: Fix bug: when file is modified, it seems the size has to be recalculated */
	/* DONE: Fix buf: When last page, content length is missing one byte */
	
	memcpy(&lastver, mmfile+coffeestart+(p*pagesize)+headersize, file_list[p].max_pages*pagesize-headersize);
	
	for (int i = 0, version = 2; i<n_logs; i++, version++){
	  /* Write one version of the file for each log entry */ 
	  uint16_t page = mmfile[coffeestart+lpage*pagesize+headersize+(i*2)] | mmfile[coffeestart+lpage*pagesize+headersize+(i*2)+1] << 8;
	  uint64_t clen; 
	  
	  if (page != 0){ /* Valid log entry */
	    snprintf(savename, 2*MAX_FILENAME, "%s/%s_%c%04x_V%04d", directory, file_list[p].name, file_list[p].type == file_active ? 'A' : 'D', p, version);
	    if (verbose > 0) printf("Writing log file: %s\n", savename);
	    /* Write start of original file */
	    of = fopen(savename, "w");
	    if (!of){
	      perror("fopen");
	      exit(EXIT_FAILURE);
	    }

	    memcpy(&lastver[(page-1)*pagesize], mmfile+coffeestart+(lpage*pagesize)+headersize+(n_logs*2)+(i*pagesize), pagesize);
	    clen = get_content_len(lastver, file_list[p].max_pages*pagesize-headersize);
	    
	    if (fwrite(lastver, clen, 1, of) == 1){
	      if (verbose > 0)
		printf("Wrote %s: 0x%lx bytes from logfile at page 0x%x (%d)\n", savename, clen, lpage, i);
	    } else { 
	      perror("fwrite");
	      exit(EXIT_FAILURE);
	    } 
	    
	    fclose(of);
	    if (hashfile[0]){
	      crypto_hash_sha256(hashval, lastver, clen);
	      byte2str(hashval, crypto_hash_sha256_BYTES, hashstr, crypto_hash_sha256_BYTES*2+1);
	      fprinthash(hashf, savename, hashstr);
	    }
	  } else {
	    /* No more log pages, as page descriptor is 0 */
	    break;
	  }
	  
	  //fwrite();
	}
      } else {
	printf("No log file? %s: %x -> %x: Flags: %x\n", file_list[p].name, file_list[p].log_page, lpage, file_list[p].flags);
      }
    }
    }

    if (dostats){
    printf("Statistics:\n  S: Tot calculated: %u\n", stats.tot_pages_calculated);
    printf("  S: Tot processed: %u\n", stats.tot_pages_processed);
    printf("  S: N active base file pages %u\n", stats.n_active_base);
    printf("  S: N active log file pages: %u\n", stats.n_active_log);
    printf("  S: N deleted base files pages: %u\n", stats.n_deleted);
    printf("  S: N deleted log file pages: %u\n", stats.n_deleted_log);
    printf("  S: N isolated: %u\n", stats.n_isolated);
    printf("  S: N Zero pages: %u\n", stats.n_zero);
    printf("  S: N unknown: %u\n", stats.n_unknown);
  }

  
  munmap(mmfile, fs.st_size);
  if (hashf){
    fclose(hashf);
  }
    
  exit(EXIT_SUCCESS);
}
