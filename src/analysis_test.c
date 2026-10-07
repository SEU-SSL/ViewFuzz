#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <elf.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <link.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define EDGE_SIZE      6
#define BB_LIST_SIZE   6
char* file_path;

#define MAP_SIZE_POW25      25
#define MAP_SIZE_25         (1 << MAP_SIZE_POW25)

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

// [+] Some macro definitions for binary analysis.
#define BFD_NO_FLAGS    0x00
#define HAS_RELOC       0x01
#define EXEC_P          0x02
#define HAS_LINENO      0x04
#define HAS_DEBUG       0x08
#define HAS_SYMS        0x10
#define HAS_LOCALS      0x20
#define DYNAMIC         0x40
#define WP_TEXT         0x80
#define D_PAGED         0x100

#define ELFW(type)      _ELFW (ELF, __ELF_NATIVE_CLASS, type)
#define _ELFW(e,w,t)    _ELFW_1 (e, w, _##t)
#define _ELFW_1(e,w,t)  e##w##t

typedef struct elf_data_s {
  Elf64_Ehdr *ehdr_64;
  Elf64_Shdr *shdr_64;
  Elf64_Sym *symbols_64;

  /*Elf32_Ehdr *ehdr_32;
  Elf32_Shdr *shdr_32;
  Elf32_Sym *symbols_32;*/
  void *data;
  unsigned char *str_symbols;
  int long symbols_size;
  int return_value;
  bool file_default;
  int file_nbr;
  char *file_path;
  long file_size;
  int fd;
} elf_data_t;

// [+] for read shm (edge_info)
typedef struct edge_info{
  int source_bb;
  int dest_bb;
  int edge_hash;
}edge_info;
struct edge_info edge_map[EDGE_SIZE*MAP_SIZE];

// [+] for read shm (bb_info)
typedef struct bb_info{
  int bb_id;
  int num_dcallsite;
  int num_indcallsite;
}bb_info;
struct bb_info bb_map[MAP_SIZE_25>>1];

//int shm_info_pro[2];

// [+] for the final bb node
typedef struct bb_node{
  int bb_id;
  int _00_skip_offset;
  int offset_i;
  int offset_j;
  int bb_to_edge[1000];  //bb_to_egde[0]存储边数，后面存储边hash
  int mark;
  int save_loc;
  int standby_loc;
} bb_node;
struct bb_node bb_list[BB_LIST_SIZE*MAP_SIZE];
int index_of_bb_list = 1;
int sum_dcall = 0;
int sum_indcall = 0;

// [+] Variables used to read shared memory for storage edge information.
int shm_edge_map_id = 0;
// [+] read shm (edge info)
void read_edge_map()
{
  FILE *info_edge = fopen("info_edge.bin", "rb");
  if (info_edge == NULL) {
    perror("fopen");
    return;
  }
  fread(edge_map, sizeof(edge_info), EDGE_SIZE*MAP_SIZE, info_edge);
  int index_of_edge = 0;
  while(edge_map[index_of_edge].source_bb != 0 && index_of_edge < EDGE_SIZE*MAP_SIZE)
  {
    printf("edge_map[%d]: edge_hash = %d, source_bb = 0x%x, dest_bb = 0x%x\n", index_of_edge, edge_map[index_of_edge].edge_hash, edge_map[index_of_edge].source_bb, edge_map[index_of_edge].dest_bb);
    index_of_edge++;
  }
  fclose(info_edge);
}

// [+] Variables used to read shared memory for storage bb information.
int shm_bb_map_id = 0;
// [+] read shm (bb info)
void read_bb_index()
{
  FILE *info_bb = fopen("info_bb.bin", "rb");
  if (info_bb == NULL) {
    perror("fopen");
    return;
  }
  fread(bb_map, sizeof(bb_info), MAP_SIZE_25>>1, info_bb);
  int index_of_bb = 0;
  for(int index_of_bb = 0; index_of_bb < (MAP_SIZE_25>>1); index_of_bb++)
  {
    if(bb_map[index_of_bb].bb_id != 0)
    {
      printf("bb_index[%d] : bb_id = %d(%x), num of direct call = %d, num of indirect call = %d\n", index_of_bb, bb_map[index_of_bb].bb_id, bb_map[index_of_bb].bb_id, bb_map[index_of_bb].num_dcallsite, bb_map[index_of_bb].num_indcallsite);
    } 
  }
  fclose(info_bb);
}


// [+] Remove the shared memory to free shm space.
void remove_shared_map()
{
  shmctl(shm_edge_map_id, IPC_RMID, NULL);
  shmctl(shm_bb_map_id, IPC_RMID, NULL);
  //int shm_fp_index_id = shmget(shm_fp_index_key, sizeof(int), IPC_CREAT | 0600);
  //shmctl(shm_fp_index_id, IPC_RMID, NULL);
}

// [+] Extract function address.

static const char *st_type(unsigned int stype)
{
  switch (stype) {
    case STT_NOTYPE: return "NOTYPE";
    case STT_OBJECT: return "OBJECT";
    case STT_FUNC: return "FUNC";
    case STT_SECTION: return "SECTION";
    case STT_FILE: return "FILE";
    case STT_COMMON: return "COMMON";
    case STT_TLS: return "TLS";
    case STT_LOOS ... STT_HIOS: return "OS_SPEC";
    case STT_LOPROC ... STT_HIPROC: return "PROC_SPEC";
    default: return "<unknown symbol type>";
  }
}

static const char *st_bind(unsigned int stbind)
{
  switch (stbind) {
    case STB_LOCAL: return "LOCAL";
    case STB_GLOBAL: return "GLOBAL";
    case STB_WEAK: return "WEAK";
//  case STB_GNU_UNIQUE: return "UNIQUE";
    case STB_LOOS ... STB_HIOS: return "OS";
    case STB_LOPROC ... STB_HIPROC: return "PROC";
    default: return "<unknown symbol bind>";
  }
}

static const char *st_vis(unsigned int svis)
{
  switch (svis) {
    case STV_DEFAULT: return "DEFAULT";
    case STV_INTERNAL: return "INTERNAL";
    case STV_HIDDEN: return "HIDDEN";
    case STV_PROTECTED: return "PROTECTED";
    default: return "<unknown symbol vis>";
  }
}

static const char *st_shndx(unsigned int shndx)
{
  static char s_shndx[32];
    switch (shndx) {
      case SHN_UNDEF: return "UND";
      case SHN_ABS: return "ABS";
      case SHN_COMMON: return "COMMON";
      case SHN_LOPROC ... SHN_HIPROC: return "PRC";
      case SHN_LOOS ... SHN_HIOS: return "OS";
      default:
        (void)snprintf(s_shndx, sizeof(s_shndx), "%u", shndx);
        return (const char *)s_shndx;
    }
}


int file_get_content(elf_data_t *elf)
{
  if ((elf->fd = (open(elf->file_path, O_RDONLY))) == -1)
    return fprintf(stderr, "my_objdump: '%s': No such file\n", elf->file_path);
  if ((elf->file_size = lseek((elf->fd), 0, SEEK_END)) == -1) {
    close(elf->fd);
    return fprintf(stderr, "my_objdump: '%s': file format not recognized\n",
    elf->file_path);
  }
  elf->data = mmap(NULL, elf->file_size, PROT_READ, MAP_SHARED, elf->fd, 0);
  if (elf->data == MAP_FAILED && elf->file_size > 0) {
    close(elf->fd);
    return fprintf(stderr, "my_objdump: '%s': file format not recognized\n",
    elf->file_path);
    }
  /* if (elf->file_nbr > 1) printf("\n%s:\n", elf->file_path); */
  return 0;
}


uint32_t get_flag_64(elf_data_t *elf)
{
  uint32_t flag = 0;
  bool is_symbol_flag = false;

  for (unsigned int i = 0; i < elf->ehdr_64->e_shnum; i++)
    if (elf->shdr_64[i].sh_type != SHT_SYMTAB || elf->shdr_64[i].sh_type != SHT_DYNAMIC)
      is_symbol_flag = true;
    if (is_symbol_flag == true)
      flag |= HAS_SYMS;
    if (elf->ehdr_64->e_type == ET_EXEC)
      flag |= EXEC_P;
    if (elf->ehdr_64->e_type == ET_REL)
      flag |= HAS_RELOC;
    if (elf->ehdr_64->e_phnum != 0)
      flag |= D_PAGED;
    if (elf->ehdr_64->e_type == ET_DYN)
      flag |= DYNAMIC;
    return flag;
}

void print_flags_64(elf_data_t *elf)
{
  int flag_print = 0;
  bool is_symbol_flag = false;

  if (elf->ehdr_64->e_type == ET_REL)
    flag_print += printf("HAS_RELOC");
  if (elf->ehdr_64->e_type == ET_EXEC)
    flag_print += printf((flag_print)? ", EXEC_P": "EXEC_P");
  for (unsigned int i = 0; i < elf->ehdr_64->e_shnum; i++)
    if (elf->shdr_64[i].sh_type != SHT_SYMTAB || elf->shdr_64[i].sh_type != SHT_DYNAMIC)
      is_symbol_flag = true;
    if (is_symbol_flag == true)
      flag_print += printf((flag_print)? ", HAS_SYMS": "HAS_SYMS");
    if (elf->ehdr_64->e_type == ET_DYN)
      flag_print += printf((flag_print)? ", DYNAMIC": "DYNAMIC");
    if (elf->ehdr_64->e_phnum != 0)
      flag_print += printf((flag_print)? ", D_PAGED": "D_PAGED");
    printf("\n");
}

int check_section_64(Elf64_Shdr *shdr, int i)
{
  return (shdr[i].sh_type != SHT_NOBITS
    && shdr[i].sh_size > 0
    && shdr[i].sh_name
    && shdr->sh_flags != SHF_INFO_LINK
    && (shdr[i].sh_addr || (!shdr[i].sh_addr
    && shdr[i].sh_type != SHT_REL
    && shdr[i].sh_type != SHT_RELA
    && shdr[i].sh_type != SHT_SYMTAB
    && shdr[i].sh_type != SHT_STRTAB))
  );
}


void find_bbid(elf_data_t *elf, int i, int j, int* bb)
{
  unsigned char *w = (unsigned char *) ((char*) elf->ehdr_64 + elf->shdr_64[i].sh_offset);
  int address_text = elf->shdr_64[i].sh_addr;
  int bb_id = 0;

  for( ; j < elf->shdr_64[i].sh_size; j++)
  {

    if(w[j] == 0xc7 && w[j+1] == 0x00 && w[j+5] == 0x00) // c7 00 xx xx xx 00 bb_id = w[j+4] w[j+3] w[j+2]
    {
      bb_id = (w[j+2]%16)*pow(16,0) + (w[j+2]/16)*pow(16,1) + (w[j+3]%16)*pow(16,2) + (w[j+3]/16)*pow(16,3) + (w[j+4]%16)*pow(16,4) + (w[j+4]/16)*pow(16,5);
      if(bb_map[bb_id].bb_id == bb_id*2) {break;}
    }

    if(w[j] == 0x64 && w[j+1] == 0xc7 && w[j+6] == 0x00) // 64 c7 xx xx xx xx 00  bb_id = w[j+5] w[j+4] w[j+3] 
    {
      bb_id = (w[j+3]%16)*pow(16,0) + (w[j+3]/16)*pow(16,1) + (w[j+4]%16)*pow(16,2) + (w[j+4]/16)*pow(16,3) + (w[j+5]%16)*pow(16,4) + (w[j+5]/16)*pow(16,5);
      if(bb_map[bb_id].bb_id == bb_id*2) {break;}
    }

    if(w[j] == 0x64 && w[j+1] == 0x41 && w[j+2] == 0xc7 && w[j+7] == 0x00) // 64 41 c7 xx xx xx xx 00  bb_id = w[j+6] w[j+5] w[j+4]
    {
      bb_id = (w[j+4]%16)*pow(16,0) + (w[j+4]/16)*pow(16,1) + (w[j+5]%16)*pow(16,2) + (w[j+5]/16)*pow(16,3) + (w[j+6]%16)*pow(16,4) + (w[j+6]/16)*pow(16,5);
      if(bb_map[bb_id].bb_id == bb_id*2) {break;}
    }

    if(w[j] == 0x64 && w[j+1] == 0xc7 && w[j+2] == 0x45 && w[j+3] == 0x00 && w[j+7] == 0x00) // 64 c7 45 00 xx xx xx 00 bb_id = w[j+6] w[j+5] w[j+4]
    {
      bb_id = (w[j+4]%16)*pow(16,0) + (w[j+4]/16)*pow(16,1) + (w[j+5]%16)*pow(16,2) + (w[j+5]/16)*pow(16,3) + (w[j+6]%16)*pow(16,4) + (w[j+6]/16)*pow(16,5);
      if(bb_map[bb_id].bb_id == bb_id*2) {break;}
    }

    if(w[j] == 0x64 && w[j+1] == 0x41 && w[j+2] == 0xc7 && w[j+8] == 0x00) // 64 41 c7 xx xx xx xx xx 00  bb_id = w[j+7] w[j+6] w[j+5]
    {
      bb_id = (w[j+5]%16)*pow(16,0) + (w[j+5]/16)*pow(16,1) + (w[j+6]%16)*pow(16,2) + (w[j+6]/16)*pow(16,3) + (w[j+7]%16)*pow(16,4) + (w[j+7]/16)*pow(16,5);
      if(bb_map[bb_id].bb_id == bb_id*2) {break;}
    }
    if(w[j] == 0xeb && w[j+1] == 0x00){
      bb_id = -1;
      break;
    }
    else{
      bb_id = -1;
    }
  }
  *bb = bb_id;
}

void find_in_edge(int* bb, int* in_edge)
{
  for(int i = 0; edge_map[i].source_bb != 0 && in_edge[0] < 1000 && i < EDGE_SIZE*MAP_SIZE; i++)
  {
    if(*bb == edge_map[i].dest_bb / 2)
    {
      in_edge[0]++;
      
      in_edge[in_edge[0]] = edge_map[i].edge_hash;
    }
  }
  return;
}

void print_section_64(elf_data_t *elf, char *str_sections, int i)//跳过多少字节
{
  int bb_id = 0;
  int* bb = &bb_id;
  int offset_i,offset_j;

  unsigned char *w = (unsigned char *) ((char*) elf->ehdr_64 + elf->shdr_64[i].sh_offset);
  
  if(!strcmp(&str_sections[elf->shdr_64[i].sh_name],".text"))
  {
    printf(".text offset = %x\n", (int)elf->shdr_64[i].sh_offset);
    
    int address_text = elf->shdr_64[i].sh_addr;

    printf("Contents of section 0x%016x:\n", address_text);

    for(unsigned int j = 0; j < elf->shdr_64[i].sh_size; j++)
    {
      int skip_num = 0;
      if(w[j] == 0x00 && w[j+1] == 0x00 && w[j+2] == 0xeb && w[j+3] == 0x00 && w[j+4] == 0x80 && w[j+7] == 0x01){ 
        offset_i = i;
        offset_j = j+3;
        j += 7;
        skip_num = 4;
        find_bbid(elf, i, j, bb);
      }
      else if(w[j] == 0x00 && w[j+1] == 0x00 && w[j+2] == 0xeb && w[j+3] == 0x00 && w[j+5] == 0x80 && w[j+8] == 0x01){
        offset_i = i;
        offset_j = j+3;
        j += 8;
        skip_num = 5;
        find_bbid(elf, i, j, bb);
      }
      else if(w[j] == 0x00 && w[j+1] == 0x00 && w[j+2] == 0xeb && w[j+3] == 0x00 && w[j+4] == 0x80 && w[j+8] == 0x01){
        offset_i = i;
        offset_j = j+3;
        j += 8;
        skip_num = 5;
        find_bbid(elf, i, j, bb);
      }
      else if(w[j] == 0x00 && w[j+1] == 0x00 && w[j+2] == 0xeb && w[j+3] == 0x00 && w[j+5] == 0x80 && w[j+9] == 0x01){
        offset_i = i;
        offset_j = j+3;
        j += 9;
        skip_num = 6;
        find_bbid(elf, i, j, bb);
      }
      else{
        continue;
      }
      if((*bb) != -1){
        int in_edge[MAP_SIZE] = {0};
        find_in_edge(bb, in_edge);
        printf("bb = 0x%x(hex), in_edge = %d : ", (*bb)*2, in_edge[0]);
        for(int p = 1; p <= in_edge[0]; p++)
        {
          printf("edge_hash = %d(dec) ", in_edge[p]);
        }
        printf("\n");
        bb_list[index_of_bb_list].bb_id = (*bb)*2;
        bb_list[index_of_bb_list]._00_skip_offset = skip_num;
        bb_list[index_of_bb_list].offset_i = offset_i;
        bb_list[index_of_bb_list].offset_j = offset_j;
        bb_list[index_of_bb_list].mark = 1;
        sum_dcall += bb_map[*bb].num_dcallsite;
        sum_indcall += bb_map[*bb].num_indcallsite;
        if(in_edge[0] > 0)
        {
          int index_edge = 1;
          for(int s = 1; s <= in_edge[0]; s++)
          {
            bool is_exit = false;
            if (s == 1){
              bb_list[index_of_bb_list].bb_to_edge[1] = in_edge[1];
              index_edge++;
            }
            else{
              for (int k = 1; k < s; k++){
                if (bb_list[index_of_bb_list].bb_to_edge[k] == in_edge[s]){
                  is_exit = true;
                }
              }
              if (!is_exit){
                bb_list[index_of_bb_list].bb_to_edge[index_edge] = in_edge[s];
                index_edge++;
              }
            }
          }
          bb_list[index_of_bb_list].bb_to_edge[0] = index_edge-1;
        }
        else{
          bb_list[index_of_bb_list].bb_to_edge[0] = 0;
        }
      }
      else{
        bb_list[index_of_bb_list].bb_id = -1;
        bb_list[index_of_bb_list]._00_skip_offset = -1;
        bb_list[index_of_bb_list].offset_i = -1;
        bb_list[index_of_bb_list].offset_j = -1;
        bb_list[index_of_bb_list].bb_to_edge[0] = 0;
        bb_list[index_of_bb_list].mark = 0;
        bb_list[index_of_bb_list].save_loc = -1;
        bb_list[index_of_bb_list].standby_loc = -1;
      }
      index_of_bb_list++;
      printf("bb_list[%d]: bb_id = %x(hex), offset_i = %d, offset_j = %d\n", index_of_bb_list-1,bb_list[index_of_bb_list-1].bb_id, bb_list[index_of_bb_list-1].offset_i,bb_list[index_of_bb_list-1].offset_j);
    }
  }
}

void sections_64(elf_data_t *elf, char *str_sections)
{
    for (int i = 0; i < elf->ehdr_64->e_shnum; i++)
        if (check_section_64(elf->shdr_64, i))
            print_section_64(elf, str_sections, i);
}

void print_objdump_64(elf_data_t *elf)
{
    char *str_sections = (char *)((char *)elf->data
    + elf->shdr_64[elf->ehdr_64->e_shstrndx].sh_offset);

    printf("architecture: i386:x86-64, flags 0x%.8x:\n", get_flag_64(elf));
    print_flags_64(elf);
    printf("start address 0x%016x\n\n", (int)elf->ehdr_64->e_entry);
    sections_64(elf, str_sections);
}

int objdump_64(elf_data_t *elf)
{
  elf->shdr_64 = (Elf64_Shdr *)((char *)elf->data + elf->ehdr_64->e_shoff);
  printf("\n%s:%5cfile format %s\n", elf->file_path, ' ', "elf64-x86-64");
  print_objdump_64(elf);
  return 0;
}

int objdump(elf_data_t *elf)
{
  // elf->file_nbr = ac - 1;
  if (file_get_content(elf)) {
    elf->return_value++;
    return 0;
  }
  elf->ehdr_64 = (Elf64_Ehdr*)elf->data;
  if (elf->ehdr_64->e_ident[EI_CLASS] == ELFCLASS64) {
    return objdump_64(elf);
  }
  else {
    perror("not elf64");
  }
}

int binary_handling(char **av)
{
    elf_data_t elf;
    elf.return_value = 0;
    elf.file_default = false;
    file_path = av[optind];
    elf.file_path = file_path;
    if(objdump(&elf) == 84)
    {
      return 84;
    }
    return elf.return_value;
}

// [+] Handling conflict cases (maximum conflict values for edges,
// [+] i.e., how many edges have equal hashes)
int conflict_edge[MAP_SIZE] = {0};
int handle_edge_conflict()
{
  int max_edge_conflict = 0;

  for(int i = 1; i < index_of_bb_list; i++)
  {
    if(bb_list[i].bb_to_edge[0] != 0)
    {
      printf("bb_list[%d].bb_to_edge[0] = %d : ", i, bb_list[i].bb_to_edge[0]);

      for(int j = 1; j <= bb_list[i].bb_to_edge[0]; j++)
      {
        int edge_hash_tmp = bb_list[i].bb_to_edge[j];
        conflict_edge[edge_hash_tmp]++;

        if(max_edge_conflict < conflict_edge[edge_hash_tmp])
        {
          max_edge_conflict = conflict_edge[edge_hash_tmp];
        }

        printf("%d ", edge_hash_tmp);
      }
      printf("\n");
    }
  }

  return max_edge_conflict;
}

void copy_binary(char* src_path, char* dst_path){

  struct stat st = {0};
  if (stat(src_path, &st) < 0)
    perror("copy_file() stat() failed on ");

  char * data = malloc(st.st_size);

  FILE * src_file = fopen(src_path, "rb");
  if (src_file == NULL)
    perror("Unable to open file ");

  FILE * dst_file = fopen(dst_path, "wb");
  if (dst_file == NULL)
    perror("Unable to open file");

  if (fread(data, 1, st.st_size, src_file) != st.st_size)
    perror("Unable to read file ");

  if(fwrite(data, 1, st.st_size, dst_file) != st.st_size) 
    perror("Unable to write file ");

  fclose(src_file);
  fclose(dst_file);
  if (chmod(dst_path, 0777) < 0)
    perror("Cannot chmod() '0777' on file ");

  Elf64_Ehdr *ehdr_64;
  Elf64_Shdr *shdr_64;
  void *fdata;
  long file_size;
  int fd;
  if ((fd = (open(dst_path, O_RDONLY))) == -1)
    perror("openfile error");

  if ((file_size = lseek((fd), 0, SEEK_END)) == -1){
    close(fd);
    perror("lseek error");
  }
  fdata=mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
  if (fdata == MAP_FAILED && file_size > 0) {
    close(fd);
    perror("mmap error");
  }
  ehdr_64 = (Elf64_Ehdr*)fdata;
  if (ehdr_64->e_ident[EI_CLASS] != ELFCLASS64)
    perror("the file is not elf64,not supported now,sry");
  shdr_64 = (Elf64_Shdr *)((char *)fdata + ehdr_64->e_shoff);
  close(fd);
  FILE* target_file=fopen(dst_path,"rb+");
  for(int i = 1; i < index_of_bb_list; i++){
    if (bb_list[i].offset_i != -1 && bb_list[i].offset_j != -1){
      unsigned char jmp_des[1];
      jmp_des[0] = bb_list[i]._00_skip_offset;
      if(fseek(target_file,(int)shdr_64[bb_list[i].offset_i].sh_offset+bb_list[i].offset_j,SEEK_SET)!= 0)
        perror("Unable to seek file ");
      if (fwrite(jmp_des, sizeof(jmp_des), sizeof(char), target_file) != 1)
        perror("Unable to write file ");  
    }
  }
  fclose(target_file);

  return;
}

void rewrite_binary(char* slice_file, int* slice_index){
  Elf64_Ehdr *ehdr_64;
  Elf64_Shdr *shdr_64;
  void *fdata;
  long file_size;
  int fd;
  if ((fd = (open(slice_file, O_RDONLY))) == -1)
    perror("openfile error");

  if ((file_size = lseek((fd), 0, SEEK_END)) == -1){
    close(fd);
    perror("lseek error");
  }
  fdata=mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
  if (fdata == MAP_FAILED && file_size > 0) {
    close(fd);
    perror("mmap error");
  }
  ehdr_64 = (Elf64_Ehdr*)fdata;
  if (ehdr_64->e_ident[EI_CLASS] != ELFCLASS64)
    perror("the file is not elf64,not supported now,sry");
  shdr_64 = (Elf64_Shdr *)((char *)fdata + ehdr_64->e_shoff);
  close(fd);

  FILE* target_file = fopen(slice_file, "rb+");
  for(int i = 0; slice_index[i] != 0; i++){
    if (bb_list[slice_index[i]].offset_i != -1 && bb_list[slice_index[i]].offset_j != -1){
      unsigned char jmp_des[1];
      jmp_des[0] = 0x00;
      if(fseek(target_file,(int)shdr_64[bb_list[slice_index[i]].offset_i].sh_offset+bb_list[slice_index[i]].offset_j,SEEK_SET)!= 0)
        perror("Unable to seek file ");
      if (fwrite(jmp_des, sizeof(jmp_des), sizeof(char), target_file) != 1)
        perror("Unable to write file ");
    }
  }
  fclose(target_file);
}


int main(int argc, char**argv)
{
  printf("\n\033[32mstep1: Read edge_map.\33[37m\n");
  read_edge_map();

  printf("\n\033[32mstep2: Read bb_map.\33[37m\n");
  read_bb_index();

  printf("\n\033[32mstep3: Read info_program.\33[37m\n");

  printf("\n\033[32mstep4: Scan the binary and extract jmp information.\33[37m\n");
  binary_handling(argv);

  int max_edge_conflict = 0;
  printf("\n\033[32mstep5: Handling edge hash conflicts \33[37m\n");
  max_edge_conflict = handle_edge_conflict();
  if(max_edge_conflict == 0) max_edge_conflict = 1;
  printf("max_edge_conflict = %d\n", max_edge_conflict);
  max_edge_conflict = max_edge_conflict*2;            //预留位置动态增补

  printf("\n\033[32mstep6: Create the hashmap[MAP_SIZE*max_edge_conflict] as a structural variable to transition to shared memory \33[37m\n");
  int size_of_hashmap = MAP_SIZE*max_edge_conflict;
  int *hashmap = (int*)malloc(sizeof(int)*size_of_hashmap);

  memset(hashmap,-1,sizeof(int)*size_of_hashmap);

  for(int i = 1; i < index_of_bb_list; i++)
  {
    if(bb_list[i].bb_to_edge[0] > 0)
    {
      int max_loc = 0;
      for(int s = 1; s <= bb_list[i].bb_to_edge[0]; s++)
      {
        int tmp_loc = 0;
        for(int j = 0; j < max_edge_conflict; j++)
        {
          if(hashmap[bb_list[i].bb_to_edge[s]*max_edge_conflict+j] == -1) // == -1 Indicates that the location is not occupied.
          {
            tmp_loc = j;
            break;
          }
        }
        if (max_loc < tmp_loc){
          max_loc = tmp_loc;
        }
      }
      for(int s = 1; s <= bb_list[i].bb_to_edge[0]; s++){
        hashmap[bb_list[i].bb_to_edge[s]*max_edge_conflict+max_loc] = i;
      }
      bb_list[i].save_loc = max_loc;
    }
    else{
      bb_list[i].save_loc = -1;
      bb_list[i].standby_loc = -1;
    }
  }

  int if_change_mark[index_of_bb_list];
  int *noconfilict_edge;
  noconfilict_edge = (int*)malloc(sizeof(int)*MAP_SIZE);
  memset(if_change_mark,0,sizeof(int)*index_of_bb_list);
  memset(noconfilict_edge,0,sizeof(int)*MAP_SIZE);
  for (int i = 0; i < MAP_SIZE; i++){
    int numofbb = 0;
    for(int j = 0; j < max_edge_conflict; j++){
      if(hashmap[i*max_edge_conflict+j] > 0){
        numofbb++;
      }
    }
    if(numofbb > 1){
      for(int j = 0; j < max_edge_conflict; j++){
        if(hashmap[i*max_edge_conflict+j] > 0){
          int index = hashmap[i*max_edge_conflict+j];
          if_change_mark[index] = 1;
        }
      }
    }
    if(numofbb == 1){
      noconfilict_edge[i] = 1;
    }
  }
  int no_change_sum;
  for (int i = 1; i < index_of_bb_list; i++){
    if (if_change_mark[i] == 0){
      no_change_sum++;
      bb_list[i].mark = 0;
    }
  }
  printf("The number of bb don't need be changed is %d.\n", no_change_sum);

  int max_mark_loc = 0;
  for(int i = 0; i < MAP_SIZE; i++){
    int mark_loc = -1;
    for(int j = 0; j < max_edge_conflict; j++){
      if(hashmap[i*max_edge_conflict+j] > 0){
        mark_loc = j;
      }
    }
    if(mark_loc != -1){
      for(int j = 0; j < mark_loc; j++){
        if(hashmap[i*max_edge_conflict+j] == -1){
          hashmap[i*max_edge_conflict+j] = 0;
        }
      }
    }
  }

  for(int i = 1; i < index_of_bb_list; i++)
  {
    if(bb_list[i].bb_to_edge[0] > 0)
    {
      int max_loc = 0;
      for(int s = 1; s <= bb_list[i].bb_to_edge[0]; s++)
      {
        int tmp_loc = 0;
        for(int j = bb_list[i].save_loc; j < max_edge_conflict; j++){
          if(hashmap[bb_list[i].bb_to_edge[s]*max_edge_conflict+j] == -1){
            tmp_loc = j;
            break;
          }
        }
        if (max_loc < tmp_loc){
          max_loc = tmp_loc;
        }
      }
      bb_list[i].standby_loc = max_loc;
    }
    else{
      bb_list[i].standby_loc = -1;
    }
  }

  printf("\n\033[32mstep7: Create the shared memory \33[37m\n");    
  
  FILE *info_hashmap = fopen("info_hashmap.bin", "wb");
  FILE *info_bb_list = fopen("info_bb_list.bin", "wb");
  FILE *info_idtoindex = fopen("info_idtoindex.bin", "wb");
  FILE *info_ncedge = fopen("info_ncedge.bin", "wb");
  FILE *info_size = fopen("info_size.bin", "wb");
  if (info_hashmap == NULL || info_bb_list == NULL || info_idtoindex == NULL || info_ncedge == NULL || info_size == NULL) {
    perror("fopen");
    return 1;
  }

  int num_edge = 0;
  for(int i = 0; i < MAP_SIZE*max_edge_conflict; i++)
  {
    if(hashmap[i] > 0){
      num_edge++;
    }
  }
  
  fwrite(hashmap, sizeof(int), MAP_SIZE*max_edge_conflict, info_hashmap);
  free(hashmap);

  bb_node *shm_bb_node;
  shm_bb_node = (bb_node*)malloc(sizeof(bb_node)*index_of_bb_list);
  int *shm_idtoindex;
  shm_idtoindex = (int*)malloc(sizeof(int)*MAP_SIZE_25);
  memset(shm_idtoindex,-1,sizeof(int)*MAP_SIZE_25);
  shm_bb_node[0].bb_id = -1;
  shm_bb_node[0]._00_skip_offset = -1;
  shm_bb_node[0].offset_i = -1;
  shm_bb_node[0].offset_j = -1;
  shm_bb_node[0].bb_to_edge[0] = 0;
  shm_bb_node[0].mark = 0;
  shm_bb_node[0].save_loc = -1;
  shm_bb_node[0].standby_loc = -1;
  for(int i = 1; i < index_of_bb_list; i++)
  {
    if(bb_list[i].bb_id > 0){
      shm_idtoindex[bb_list[i].bb_id] = i;
    }
    shm_bb_node[i].bb_id = bb_list[i].bb_id;
    shm_bb_node[i]._00_skip_offset = bb_list[i]._00_skip_offset;
    shm_bb_node[i].bb_to_edge[0] = bb_list[i].bb_to_edge[0];
    shm_bb_node[i].offset_i = bb_list[i].offset_i;
    shm_bb_node[i].offset_j = bb_list[i].offset_j;
    shm_bb_node[i].mark = bb_list[i].mark;
    shm_bb_node[i].save_loc = bb_list[i].save_loc;
    shm_bb_node[i].standby_loc = bb_list[i].standby_loc;
    if(shm_bb_node[i].bb_to_edge[0] > 0)
    {
      for(int j = 1; j <= shm_bb_node[i].bb_to_edge[0]; j++)
      {
        shm_bb_node[i].bb_to_edge[j] = bb_list[i].bb_to_edge[j];
      }
    }
  }
  fwrite(shm_bb_node, sizeof(bb_node), index_of_bb_list, info_bb_list);
  fwrite(shm_idtoindex, sizeof(int), MAP_SIZE_25, info_idtoindex);
  free(shm_bb_node);
  free(shm_idtoindex);

  fwrite(noconfilict_edge, sizeof(int), MAP_SIZE, info_ncedge);
  free(noconfilict_edge);

  printf("\nmax_edge_conflict = %d, index_of_bb_list(numofbb) = %d, num of edges = %d\n", max_edge_conflict/2, index_of_bb_list-1, num_edge);
  printf("The num of direct call sites is %d, the num of indirect call sites is %d\n", sum_dcall, sum_indcall);
  double tmp_1 = (MAP_SIZE - 1.0) / MAP_SIZE;
  double tmp_2 = pow(tmp_1, num_edge);
  double collision_rate = 1.0 - ((double)MAP_SIZE / num_edge) * (1 - tmp_2);
  printf("The collision rate(exclude sites) of :%lf\n", collision_rate);
  num_edge = num_edge + sum_dcall + sum_indcall;
  tmp_2 = pow(tmp_1, num_edge);
  collision_rate = 1.0 - ((double)MAP_SIZE / num_edge) * (1 - tmp_2);
  printf("The collision rate(include sites) of :%lf\n", collision_rate);


  printf("\n\033[32mstep8: Pass the variable controlling the two shared memory values to afl-llvm-rt.o.c \33[37m\n");

  int shm_size_info[2];
  shm_size_info[0] = max_edge_conflict;
  shm_size_info[1] = index_of_bb_list;
  fwrite(shm_size_info, sizeof(int), 2, info_size);

  fclose(info_bb_list);
  fclose(info_hashmap);
  fclose(info_idtoindex);
  fclose(info_ncedge);
  fclose(info_size);

  return 0;
}  
