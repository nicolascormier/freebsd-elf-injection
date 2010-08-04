/*
** elf.c for  in /home/nico/lang/c/jambi-partI
** 
** Made by nicolas
** Mail   <n.cormier@gmail.com>
** 
** Started on  Thu Jan 18 18:42:15 2007 nicolas
** Last update Thu Jan 25 12:26:49 2007 nicolas
*/

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <strings.h>

#include "jambi.h"

static elfbin_t*	_create_elfbin(const char* path);
static void		_delete_elfbin(elfbin_t* to_delete);
static int		_change_binary_size(off_t new_size, elfbin_t* out);
static Elf_Addr		_get_entry_point_addr(elfbin_t* bin);


/***************************************************************************
	Exported functions

  Prototypes declared in jambin.h

***************************************************************************/

elfbin_t*	create_elfbin(const char* path)
{
  return _create_elfbin(path);
}

void	delete_elfbin(elfbin_t* to_delete)
{
  return _delete_elfbin(to_delete);
}

int	increase_binary_size(off_t new_size, elfbin_t* out)
{
  if (!out || new_size <= out->rsize)
    return -1;
  return _change_binary_size(new_size, out);
}

Elf_Addr	get_entry_point_addr(elfbin_t* bin)
{
  return _get_entry_point_addr(bin);
}

/***************************************************************************
	Static functions

***************************************************************************/

static Elf_Addr	_get_entry_point_addr(elfbin_t* bin)
{
  unsigned	i;
  Elf_Shdr*	shdr = NULL;
  Elf_Sym*	start, * end;
  char*		sym_str;

  for (i = 0; bin->section_headers[i]; i++)
    {
      if (!strcmp(bin->section_headers[i]->sh_name + bin->section_str, ".symtab"))
	shdr = bin->section_headers[i];
    }
  if (!shdr)
    return 0;
  start = (Elf_Sym *) ((char*) bin->header + shdr->sh_offset);
  end   = (Elf_Sym *) ((char*) bin->header + shdr->sh_offset + shdr->sh_size);
  sym_str = ((char*)bin->header + bin->section_headers[shdr->sh_link]->sh_offset);
  for (; start < end; start++)
    {
      if (!strcmp(sym_str + start->st_name, "main"))
	return start->st_value;
    }
  return 0;
}


static int	_change_binary_size(off_t new_size, elfbin_t* out)
{
  void*		old_data;
  int		diff;
  unsigned	i;
  char*		ptr;

  if (!out || out->fd <= 0 || !out->data)
    {
      fprintf(stderr, "_change_binary_size: bad elfbin object\n");
      return -1;
    }
  /* Change file size
   */
  if (ftruncate(out->fd, new_size) == -1)
    {
      perror("open_binary:ftruncate");
      return -1;
    }
  /* Remap
   */
  old_data = out->data;
  munmap(out->data, out->rsize);
  out->data = mmap(old_data, new_size, PROT_READ|PROT_WRITE, MAP_SHARED, out->fd, 0);
  if (!out->data)
    {
      perror("open_binary:mmap");
      return -1;
    }
  out->rsize = new_size;
  if (old_data == out->data)
    return 0;
  /* Sync pointers
   */
  if (old_data < out->data)
    diff = (char*)out->data - (char*)old_data;
  else
    diff = -((char*)old_data - (char*)out->data);
  ptr = (char*)out->header + diff;
  out->header = (Elf_Ehdr*)ptr;
  for (i = 0; out->program_headers && out->program_headers[i]; i++)
    {
      ptr = (char*)out->program_headers[i] + diff;
      out->program_headers[i] = (Elf_Phdr*)ptr;
    }
  for (i = 0; out->section_headers && out->section_headers[i]; i++)
    {
      ptr = (char*)out->section_headers[i] + diff;
      out->section_headers[i] = (Elf_Shdr*)ptr;
    }
  out->section_str = (char*)out->section_str + diff;
  return 0;
}

static int	_open_binary(const char* path, elfbin_t* out)
{
  int		fd = -1;
  struct stat	sb;
  void*		data = NULL;

  if ((fd = open(path, O_RDWR)) == -1)
    return -1;
  if (fstat(fd, &sb) == -1)
    {
      perror("open_binary:fstat");
      goto open_binary_failed;
    }
  data = mmap(0, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (!data)
    {
      perror("open_binary:mmap");
      goto open_binary_failed;
    }
  if (!IS_ELF(*((Elf_Ehdr*)data)))
    {
      fprintf(stderr, "open_binary:is_elf: not an elf object");
      goto open_binary_failed;
    }
  /* Feel output
   */
  out->fd = fd;
  out->rsize = out->size = sb.st_size;
  out->data = data;
  return 0;

 open_binary_failed:
  if (fd != -1)
    (void) close(fd);
  if (data)
    (void) munmap(data, sb.st_size);
  return -1;
}

static int	_fill_elfbin(elfbin_t* out)
{
  Elf_Ehdr*	header;
  Elf_Shdr**	section_headers = NULL;
  Elf_Phdr**	program_headers = NULL;
  char*		section_str, * ptr;
  int		i;

  if (!out->data)
    return -1;
  header = (Elf_Ehdr*)out->data;
  /* Program headers
   */
  program_headers = (Elf_Phdr**) malloc(sizeof(Elf_Phdr *) * (header->e_phnum + 1));
  if (program_headers == NULL)
    {
      perror("open_binary:malloc");
      goto fill_elfbin_failed;
    }
  for (ptr = (char*) header + header->e_phoff, i = 0; i < header->e_phnum; i++)
    {
      program_headers[i] = (Elf_Phdr *) ptr;
      ptr += header->e_phentsize;
    }
  program_headers[i] = NULL;
  /* Section headers
   */
  section_headers = (Elf_Shdr**) malloc(sizeof(Elf_Shdr *) * (header->e_shnum + 1));
  if (section_headers == NULL)
    {
      perror("open_binary:malloc");
      goto fill_elfbin_failed;
    }
  for (ptr = (char*) header + header->e_shoff, i = 0; i < header->e_shnum; i++)
    {
      section_headers[i] = (Elf_Shdr *) ptr;
      ptr += header->e_shentsize;
    }
  section_headers[i] = NULL;
  /* Section strng
   */
  if (header->e_shstrndx != SHN_UNDEF)
    section_str = out->data + section_headers[header->e_shstrndx]->sh_offset;
  else
    section_str = NULL;
  /* Fill output
   */
  out->header = header;
  out->program_headers = program_headers;
  out->section_headers = section_headers;
  out->section_str = section_str;
  return 0;

 fill_elfbin_failed:
  if (program_headers)
    free(program_headers);
  if (section_headers)
    free(section_headers);
  return -1;
}

static void	_free_elfbin(elfbin_t* in)
{
  if (in->program_headers)
    free(in->program_headers);
  if (in->section_headers)
    free(in->section_headers);
  if (in->data)
    (void) munmap(in->data, in->rsize);
  if (in->fd > 0)
    (void) close(in->fd);
}

static elfbin_t*	_create_elfbin(const char* path)
{
  elfbin_t* ret = (elfbin_t*) malloc(sizeof(elfbin_t));
  bzero(ret, sizeof(elfbin_t));
  if (!ret)
    return NULL;
  if (_open_binary(path, ret) || _fill_elfbin(ret))
    {
      _free_elfbin(ret);
      free(ret);
      return NULL;
    }
  return ret;
}

static void	_delete_elfbin(elfbin_t* to_delete)
{
  _free_elfbin(to_delete);
  free(to_delete);
}
