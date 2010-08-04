/*
** jambi.h for  in /home/nico/lang/c/jambi-partI
** 
** Made by nicolas
** Mail   <n.cormier@gmail.com>
** 
** Started on  Thu Jan 18 17:59:52 2007 nicolas
** Last update Thu Jan 25 11:46:52 2007 nicolas
*/

#ifndef __JAMBI_H__
# define __JAMBI_H__

# include <sys/types.h>
# include <elf.h>


# ifdef __NetBSD__
#  define ELFSIZE 32
#  define Elf_Ehdr	Elf32_Ehdr
#  define Elf_Shdr	Elf32_Shdr
#  define Elf_Phdr	Elf32_Phdr
#  define Elf_Sym	Elf32_Sym
#  define Elf_Addr	Elf32_Addr
#  define IS_ELF(ehdr)    ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
                          (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
                          (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
                          (ehdr).e_ident[EI_MAG3] == ELFMAG3)
# endif /* __NetBSD__ */

# define SECTION_SIZE	4096

struct elfbin_s
{
  /* File data */
  int		fd; /* Binary descriptor */
  off_t		size; /* Binary size */
  off_t		rsize; /* Real binary size */
  void*		data; /* Binarey mmap address */
  /* Elf data */
  Elf_Ehdr*	header; /* ELF header address */
  Elf_Shdr**	section_headers; /* Elf section headers address */
  Elf_Phdr**	program_headers; /* Elf program headers address */
  char*		section_str; /* ELF section string */
};
typedef struct elfbin_s	elfbin_t;

/* elf.c
 */
elfbin_t*	create_elfbin(const char* path);
void		delete_elfbin(elfbin_t* to_delete);
int		increase_binary_size(off_t new_size, elfbin_t* out);
Elf_Addr	get_entry_point_addr(elfbin_t* bin);

/* inject.c
 */
int		inject_section(elfbin_t* bin, const char* section_name, 
			       void* data_to_inject, off_t size_to_inject);

#endif /* __JAMBI_H__ */
