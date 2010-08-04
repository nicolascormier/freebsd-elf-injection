/*
** jambi.c for  in /home/nico/lang/c/jambi-partI
** 
** Made by nicolas
** Mail   <n.cormier@gmail.com>
** 
** Started on  Thu Jan 18 17:54:52 2007 nicolas
** Last update Thu Jan 25 13:00:09 2007 nicolas
*/

#include <stdio.h>
#include "jambi.h"

static int	_inject_new_section(elfbin_t* bin, const char* name, void* data_to_inject, off_t size)
{
  off_t		first_section_offset;
  unsigned int	i;


  if (!bin || !bin->section_headers || !*bin->section_headers)
    {
      fprintf(stderr, "push_new_section: bad section headers !\n");
      return -1;
    }
  /* Increase binary size for injection
   */
  if (increase_binary_size(bin->size + SECTION_SIZE, bin) == -1)
    return -1;
  /* Add new section
   */
  if (inject_section(bin, name, data_to_inject, size) == -1)
    return -1;
  
  return 0;
}

static void	_dump_shdr(elfbin_t* bin)
{
  unsigned i;


  if (!bin)
    return;
  for (i = 0; bin->section_headers[i]; i++)
    printf("[%d] %s {%d}\n", i, bin->section_headers[i]->sh_name + bin->section_str,
	   bin->section_headers[i]->sh_name);
}

static void	_dump_phdr(elfbin_t* bin)
{
  unsigned	i, j;
  char*		type_str = NULL;


  if (!bin)
    return;
  printf("section str mapped @ 0x%x\n", bin->section_str);
  for (i = 0; bin->program_headers && bin->program_headers[i]; i++)
    {
      Elf_Phdr* phdr = bin->program_headers[i];
      switch (phdr->p_type)
	{
	case PT_NULL:
	  type_str = "PT_NULL";
	  break;
	case PT_LOAD:
	  type_str = "PT_LOAD";
	  break;
	case PT_DYNAMIC:
	  type_str = "PT_DYNAMIC";
	  break;
	case PT_INTERP:
	  type_str = "PT_INTERP";
	  break;
	case PT_NOTE:
	  type_str = "PT_NOTE";
	  break;
	case PT_SHLIB:
	  type_str = "PT_SHLIB";
	  break;
	case PT_PHDR:
	  type_str = "PT_PHDR";
	  break;
	default:
	  continue;
	}
      printf("[%d] %s	", i, type_str);
      for (j = 0; bin->section_headers && bin->section_headers[j]; j++)
	{
	  Elf_Shdr* shdr = bin->section_headers[j];
	  if (shdr->sh_offset >= phdr->p_offset && shdr->sh_offset + shdr->sh_size <= phdr->p_offset + phdr->p_filesz)
	    if (bin->section_str && *(shdr->sh_name + bin->section_str))
	      printf("%s (%d)", shdr->sh_name + bin->section_str, shdr->sh_name);
	}
      printf("\n");
    }
}

char shellcode[] = 
"\xe9\x19\x0\x0\x0"
"\x5b"
"\x68\x0d\x0\x0\x0"
"\x53"
"\x68\x01\x0\x0\x0"
"\xb8\x04\x0\x0\x0"
"\x50"
"\xcd\x80"
"\xe9\x12\x0\x0\x0"
"\xe8\xe2\xff\xff\xff"
"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\xa";


int main(int argc, char** argv)
{
  elfbin_t* bin;;

  if (!argv[1])
    {
      printf("./jambi binary-to-patch\n");
      return 0;
    }
  bin = create_elfbin(argv[1]);
  if (!bin)
    {
      fprintf(stderr, "burk!\n");
      return 1;
    }
  if (_inject_new_section(bin, ".jambi", shellcode, sizeof(shellcode) - 1) == -1)
    fprintf(stderr, "injection failed!\n");
  else
    printf("injection succeeded\n");
  delete_elfbin(bin);

  return 0;
}
