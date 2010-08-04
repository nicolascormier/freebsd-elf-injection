/*
** patch.c for  in /home/nico/lang/c/jambi-partI
** 
** Made by nicolas
** Mail   <n.cormier@gmail.com>
** 
** Started on  Wed Jan 24 15:59:15 2007 nicolas
** Last update Thu Jan 25 11:47:05 2007 nicolas
*/

#include <stdio.h>
#include "jambi.h"

#define SECTION_STRING_TABLE	bin->section_headers[bin->header->e_shstrndx]

static int	_inject_section(elfbin_t* bin, const char* section_name, 
				void* data_to_inject, off_t size_to_inject);


/***************************************************************************
	Exported functions

  Prototypes declared in jambi.h

***************************************************************************/

int	inject_section(elfbin_t* bin, const char* section_name, 
		       void* data_to_inject, off_t size_to_inject)
{
  return _inject_section(bin, section_name, data_to_inject, size_to_inject);
}


/***************************************************************************
	Static functions

***************************************************************************/

/* Inject data in binary at a specific offset,
   we assume that bin has already been resized
 */
static int	_inject_data(elfbin_t* bin, off_t at_off, void* data, off_t data_size)
{
  off_t	post_data_size;
  char* post_data;
  char* inject_addr;


  if (!bin)
    return -1;
  /* Backup
   */
  post_data_size = bin->size - at_off;
  post_data = (char*)malloc(post_data_size);
  inject_addr = (char*)bin->data + at_off;
  if (!post_data)
    {
      perror("_inject_data:malloc:");
      return -1;
    }
  /* Inject
   */
  (void) memcpy(post_data, inject_addr, post_data_size);
  (void) memcpy(inject_addr, data, data_size);
  (void) memcpy(inject_addr + data_size, post_data, post_data_size);
  free(post_data);
  /* Update binary size
   */
  bin->size += data_size;
  return 0;
}

/* Rebuil offset in headers
   update offset after date injection
   we assume that no data has been injected in headers.
 */
static void	_patch_offset(elfbin_t* bin, off_t inject_offset, off_t inject_size)
{
  unsigned	i;
  char*		ptr;
  Elf_Shdr*	shdr;


  /* Patch elf header
   */
  bin->header->e_shoff += inject_size;
  
  /* Patch program header
   */
  for (i = 0; bin->program_headers && bin->program_headers[i]; i++)
    {
      Elf_Phdr* phdr = bin->program_headers[i];
      if (phdr->p_offset >= inject_offset)
	phdr->p_offset += inject_size;
    }
  /* Rebuild and patch section header
   */
  ptr = (char*)bin->header + bin->header->e_shoff;
  for (i = 0; i < bin->header->e_shnum; i++)
    {
      bin->section_headers[i] = (Elf_Shdr*)ptr;
      ptr += bin->header->e_shentsize;
      shdr = bin->section_headers[i];
      if (shdr->sh_offset >= inject_offset)
	shdr->sh_offset += inject_size;      
    }
  if ((char*)bin->section_str - (char*)bin->data >= inject_offset)
    bin->section_str += inject_size;
}

/* Add a string to elf file's string table,
   we assume that bin has already been resized
 */
static int	_inject_and_patch_string_table(elfbin_t* bin, const char* name)
{
  off_t patch_off;
  off_t	patch_size;
  off_t section_str_off;


  if (!bin || !bin->section_str)
    return -1;

  patch_off = SECTION_STRING_TABLE->sh_offset + SECTION_STRING_TABLE->sh_size;
  patch_size = strlen(name) + 1;
  section_str_off = bin->section_str - (char*)bin->data;

  if (_inject_data(bin, patch_off, (void*)name, patch_size) == -1)
    return -1;
  SECTION_STRING_TABLE->sh_size += patch_size;
  /* Update offsets
   */
  _patch_offset(bin, patch_off, patch_size); /* Update offsets */
  return patch_off - section_str_off; /* Offset of new entry in string table */
}

/* Add section header to section headers table
   we assume that bin has already been resized
 */
static int	_inject_and_patch_section_headers(elfbin_t* bin, off_t name_off, 
						  off_t data_off, off_t data_size)
{
  off_t		patch_off;
  unsigned	i;
  Elf_Shdr	new_shdr;


  if (!bin || !bin->section_headers)
    return -1;

  /* Seek for last section headers table entry
   */
  for (i = 0; bin->section_headers[i]; i++);
  if (!i)
    {
      fprintf(stderr, "_patch_section_headers: bad section headers table\n");
      return -1;
    }
  patch_off = (char*)bin->section_headers[i - 1] - (char*)bin->data + bin->header->e_shentsize;
  /* Init new header
   */
  new_shdr = *(bin->section_headers[1]); /* Same as interp */
  new_shdr.sh_name = name_off;
  new_shdr.sh_offset = data_off;
  new_shdr.sh_size = data_size;
  /* Inject
   */
  if (_inject_data(bin, patch_off, &new_shdr, bin->header->e_shentsize) == -1)
    return -1;
  /* Update
   */
  bin->header->e_shnum++;
  bin->section_headers = (Elf_Shdr**)realloc(bin->section_headers, 
					     sizeof(Elf_Shdr *) * (bin->header->e_shnum + 1));
  if (!bin->section_headers)
    {
      perror("_patch_section_headers:malloc:");
      return -1;
    }
  bin->section_headers[i] = (Elf_Shdr*)((char*)bin->data + patch_off);
  bin->section_headers[i + 1] = NULL;
  return 0;
}

/* Get the first rx program header
 */
static Elf_Phdr*	_rx_phdr(elfbin_t* bin)
{
  Elf_Phdr*	phdr, * rx_phdr = NULL;
  unsigned	i;


  if (!bin || !bin->program_headers)
    return NULL;
  for (i = 0; bin->program_headers[i]; i++)
    {
      phdr = bin->program_headers[i];
      if (phdr->p_type == PT_LOAD && phdr->p_flags == PF_R+PF_X)
	rx_phdr = phdr;
    }
  if (!rx_phdr)
    fprintf(stderr, "No rx phdr found\n");
  return rx_phdr;
}

/* Patch program headers
   update rx program header
   update addresses 
*/
static int	_patch_program_headers(elfbin_t* bin, off_t patch_size)
{
  Elf_Phdr*	rx_phdr, * phdr;
  unsigned	i;


  if (!bin || !bin->program_headers)
    return -1;
  /* Seek rx program header
   */
  rx_phdr = _rx_phdr(bin);
  if (!rx_phdr)
    return -1;
  rx_phdr->p_vaddr -= patch_size;
  rx_phdr->p_paddr -= patch_size;
  rx_phdr->p_filesz += patch_size;
  rx_phdr->p_memsz += patch_size;
  for (i = 0; bin->program_headers[i]; i++)
    {
      phdr = bin->program_headers[i];
      if (phdr->p_type == PT_PHDR)
	{
	  phdr->p_vaddr -= patch_size;
	  phdr->p_paddr -= patch_size;
	}
    }
  return 0;
}

/* Patch elf header
   change the binary's entry point
*/
static int	_patch_elf_header(elfbin_t* bin, off_t patch_off, off_t patch_size)
{
  Elf_Phdr*	rx_phdr;


  if (!bin || !bin->header || !bin->program_headers)
    return -1;
  /* Seek rx program header
   */
  rx_phdr = _rx_phdr(bin);
  if (!rx_phdr)
    return -1;
  bin->header->e_entry = rx_phdr->p_paddr - patch_size + patch_off;
  return 0;
}

/* Prepare and alloc data to inject
 */
static char epilogue_code[] =
"\x89\xe5"
"\xb8\x0\x0\x0\x0"	// mov $0x8048728,%eax
/* "\xff\e0"		// jmp *%eax */
"\xff\xd0"		// call %eax
"\x6a\x2a"		// push $0x2a
"\x6a\x0"		// push $0x0
"\xb8\x01\x00\x00\x00"	// mov $0x1,%eax
"\xcd\x80"		// int $0x80
;

static char*	_alloc_data_to_inject(elfbin_t* bin, void* data_to_inject, off_t size)
{
  char* to_inject;
  off_t	to_inject_size = size + sizeof(epilogue_code);
  int*	old_entry_point;

  to_inject = (char*)malloc(SECTION_SIZE);
  if (!to_inject)
    {
      perror("_alloc_data_to_inject:malloc");
      return NULL;
    }
  memcpy(to_inject, data_to_inject, size);
  memcpy((char*)to_inject + size, epilogue_code, sizeof(epilogue_code));
  /* Change old entry point value
   */
  old_entry_point = (int*)((char*)to_inject + size + 3);
  *old_entry_point = get_entry_point_addr(bin);//bin->header->e_entry;
  memset(to_inject + to_inject_size, 0, SECTION_SIZE - to_inject_size);
  return to_inject;
}


/* Add section to binary
   we assume that bin has already been resized
 */
static int	_inject_section(elfbin_t* bin, const char* section_name, 
				void* data_to_inject, off_t data_to_inject_size)
{
  off_t		patch_off = 0, name_off = 0;
  void*		data_prepared = NULL;
  off_t		size = SECTION_SIZE;

  if (!bin || !bin->program_headers || !bin->section_headers)
    return -1;
  /* Prepare data for injection
   */
  data_prepared = _alloc_data_to_inject(bin, data_to_inject, data_to_inject_size);
  if (!data_prepared)
    return -1;
  /* Inject on top of sections
   */
  patch_off = sizeof(Elf_Ehdr) + (sizeof(Elf_Phdr) * bin->header->e_phnum);
  if (_inject_data(bin, patch_off, data_prepared, size) == -1)
    goto _INJECT_SECTION_FAILED;
  /* Update offsets
   */
  _patch_offset(bin, patch_off, size); /* Update offsets */
  /* Patch elf header
   */
  if (_patch_elf_header(bin, patch_off, size) == -1)
    goto _INJECT_SECTION_FAILED;
  /* Patch program header
   */
  if (_patch_program_headers(bin, size) == -1)
    goto _INJECT_SECTION_FAILED;
  /* Add section name to string section
   */
  name_off = _inject_and_patch_string_table(bin, section_name);
  if (name_off == -1)
    goto _INJECT_SECTION_FAILED;
  /* Add new section entry to section header table
   */
  if (_inject_and_patch_section_headers(bin, name_off, patch_off, size) == -1)
    goto _INJECT_SECTION_FAILED;
  free(data_prepared);
  return 0;

 _INJECT_SECTION_FAILED:
  if (data_prepared)
    free(data_prepared);
  return -1;
}
