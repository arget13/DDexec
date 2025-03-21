/* Compile with -fno-stack-protector -nostdlib */
#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__)
    #define JMP(addr) asm volatile("jmp *%0;" : : "r"(addr))
    #define SP        "rsp"
#elif defined(__aarch64__)
    #define JMP(addr) asm volatile("br   %0;" : : "r"(addr))
    #define SP        "sp"
#endif

void*         load(void*, void*, int*);
Elf64_Addr    search_section(void*, char*, int);
void*         read_elf(size_t*);
void*         map_file(const char*, size_t*);
char**        read_args();
unsigned long hex2val(const char*);

#define IS_PIE    (1 << 0)
#define IS_STATIC (1 << 1)
#define SECTION_ADDR   0
#define SECTION_OFFSET 1

#define ARGS_FD      8
#define AUXV_ENTRIES 8
#define PIE_BASE     (void*) 0x400000
#define LD_BASE      (void*) 0x40400000 // 1GiB distance wrt binary

void _start()
{
    // Forces gcc to use x29 (fp) in this function (important bc of allocas)
    // (no, -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer didn't work)
#if defined(__aarch64__)
    alloca(0x10);
#endif

    int argc;
    char** argv = read_args(&argc);

    size_t filesz;
    int info;
    void* elf_addr = read_elf(&filesz);
    Elf64_Addr base = (Elf64_Addr) load(elf_addr, PIE_BASE, &info);

    // From the just loaded ELF get its loader (if any) and load it too
    // If it is not on the system, well, too bad.
    Elf64_Addr ldbase = 0, ldentry = 0;
    if (!(info & IS_STATIC))
    {
        size_t ldlen;
        off_t ld_path = search_section(elf_addr, ".interp", SECTION_OFFSET);
        void* ld_addr  = map_file(elf_addr + ld_path, &ldlen);
        ldbase  = (Elf64_Addr) load(ld_addr, LD_BASE, NULL);
        ldentry = ((Elf64_Ehdr*) ldbase)->e_entry + ldbase;
        munmap(ld_addr, ldlen);
    }

    uint64_t entry, phnum, phentsize, phaddr;
    entry     = ((Elf64_Ehdr*) elf_addr)->e_entry + base * !!(info & IS_PIE);
    phnum     = ((Elf64_Ehdr*) elf_addr)->e_phnum;
    phentsize = ((Elf64_Ehdr*) elf_addr)->e_phentsize;
    phaddr    = ((Elf64_Ehdr*) elf_addr)->e_phoff + base;
    munmap(elf_addr, filesz);

    // Allocate and prepare a new stack
    char* stack = (void*) mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0);
    void** newsp = (void**) &stack[0x21000];
    *--newsp = NULL; // End of stack

    if (argc & 1)
        *--newsp = NULL; // Keep stack aligned

    uint64_t random[2] = { 42, 42 };
    int i = 0;
    newsp -= AUXV_ENTRIES * 2;
    Elf64_auxv_t* auxv = (Elf64_auxv_t*) newsp;
    auxv[i].a_type = AT_PAGESZ; auxv[i++].a_un.a_val = 0x1000;
    auxv[i].a_type = AT_RANDOM; auxv[i++].a_un.a_val = (long) random;
    auxv[i].a_type = AT_ENTRY ; auxv[i++].a_un.a_val = entry;
    auxv[i].a_type = AT_BASE  ; auxv[i++].a_un.a_val = ldbase;
    auxv[i].a_type = AT_PHNUM ; auxv[i++].a_un.a_val = phnum;
    auxv[i].a_type = AT_PHENT ; auxv[i++].a_un.a_val = phentsize;
    auxv[i].a_type = AT_PHDR  ; auxv[i++].a_un.a_val = phaddr;
    auxv[i].a_type = AT_NULL  ; auxv[i++].a_un.a_val = 0;
    *--newsp = NULL; // End of envp
    *--newsp = NULL; // End of argv
    newsp -= argc; memcpy(newsp, argv, argc * sizeof(*argv));
    *(size_t*) --newsp = argc;

    dup2(2, 0);
    dup2(2, 1);

    register volatile void* sp asm(SP);
    sp = newsp;

    if (info & IS_STATIC)
        JMP(entry);
    else
        JMP(ldentry);
    __builtin_unreachable();
}

inline __attribute__((always_inline))
char** read_args(int* argcp)
{
    char buf[9];
    buf[read(ARGS_FD, buf, sizeof(buf) - 1)] = '\0';
    size_t args_len = hex2val(buf);

    // The kernel adds an empty argv[0] if none is provided
    // and some shitty programs rely on this (looking at you busybox)
    if (args_len == 0)
    {
        char** argv = alloca(2 * sizeof(*argv));
        argv[1] = NULL;
        argv[0] = (void*) &argv[1]; // An empty string
        return argv;
    }

    char* args = alloca(args_len);
    read(ARGS_FD, args, args_len);
    close(ARGS_FD);

    // De-escape characters
    int argc = 0;
    for (size_t i = 1, j = 0; i < args_len; ++i, ++j)
    {
        if (args[i] == '"')
            args[j] = '\0', i++, argc++;
        else
        if (args[i] == '\\' && ++i < args_len)
            args[j] = args[i];
        else
            args[j] = args[i];
    }

    char** argv = alloca((argc + 1) * sizeof(*argv));
    for (size_t i = 0; i < argc; ++i)
    {
        argv[i] = args;
        args += strlen(args) + 1;
    }
    argv[argc] = NULL;

    *argcp = argc;
    return argv;
}

void* load(void* elf, void* rebase, int* info)
{
    Elf64_Addr base = 0;
    Elf64_Ehdr* ehdr = elf;
    Elf64_Phdr* phdr = elf + ehdr->e_phoff;
    uint16_t phnum = ehdr->e_phnum;
    Elf64_Addr bss = search_section(elf, ".bss", SECTION_ADDR);
    if (info != NULL)
        *info = IS_STATIC;

    if (ehdr->e_type == ET_DYN) // PIE
    {
        if (info != NULL) *info |= IS_PIE;
    }
    else
        rebase = NULL;

    for (int i = 0; i < phnum; ++i)
    {
        if (info != NULL && phdr[i].p_type == PT_INTERP) *info &= ~IS_STATIC;
        if (phdr[i].p_type != PT_LOAD) continue;

        uint32_t   flags   = phdr[i].p_flags;
        Elf64_Off  offset  = phdr[i].p_offset;
        Elf64_Addr vaddr   = phdr[i].p_vaddr;
        uint64_t   filesz  = phdr[i].p_filesz;
        uint64_t   memsz   = phdr[i].p_memsz;
        Elf64_Addr aligned = vaddr & ~0xfff;

        // Convert the ELF permissions to mmap permissions
        // (why do we have two standards for permissions?)
        uint32_t prot = ((flags & PF_R) ? PROT_READ  : 0) |
                        ((flags & PF_W) ? PROT_WRITE : 0) |
                        ((flags & PF_X) ? PROT_EXEC  : 0);

        // Adjust the file size and memory size for alignment
        filesz += vaddr - aligned;
        memsz  += vaddr - aligned;
        offset -= vaddr - aligned;

        mmap(rebase + aligned, memsz, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        
        if (offset == 0) base = aligned;

        // Populate entire pages (the kernel does it this way)
        filesz = (filesz + 0xfff) & ~0xfff;

        // If the .bss section is within this segment adjust the size
        // we copy from the file to keep it (the bss) initialized to NULL's
        if (bss != -1ul && (bss >= aligned && bss < (aligned + filesz)))
            filesz = bss - aligned;
        
        memcpy(rebase + aligned, elf + offset, filesz);
        mprotect(rebase + aligned, filesz, prot);
    }

    return rebase + base;
}

void* map_file(const char* path, size_t* sz)
{
    int f;
    void* addr;

    f = openat(AT_FDCWD, path, O_RDONLY);
    *sz = lseek(f, 0, SEEK_END);
    addr = mmap(NULL, *sz, PROT_READ, MAP_PRIVATE, f, 0);
    close(f);
    return addr;
}

Elf64_Addr search_section(void* elf, char* section, int offset)
{
    Elf64_Ehdr* ehdr = elf;
    Elf64_Shdr* shdr = elf + ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint16_t shstrndx = ehdr->e_shstrndx;

    // The section header string table holds the section names
    char* shstrtab = elf + shdr[shstrndx].sh_offset;

    for (int i = 0; i < shnum; ++i)
        if (!strcmp(&shstrtab[shdr[i].sh_name], section))
        {
            if (offset)
                return shdr[i].sh_offset;
            return shdr[i].sh_addr;
        }
    return -1ul;
}

void* read_elf(size_t* flen)
{
    uint8_t* addr = (void*) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t len = 0;
    ssize_t ret;
    while ((ret = read(0, &addr[len], 0x1000)) > 0)
    {
        len += ret;
        addr = mremap(addr, len, len + 0x1000, MREMAP_MAYMOVE);
    }

    *flen = len;
    return addr;
}

#include <sys/types.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
    #define SYSCALL_ARG0 "rdi"
    #define SYSCALL_ARG1 "rsi"
    #define SYSCALL_ARG2 "rdx"
    #define SYSCALL_ARG3 "r10"
    #define SYSCALL_ARG4 "r8"
    #define SYSCALL_ARG5 "r9"
    #define SYSCALL_NR   "rax"
    #define SYSCALL_RET  "rax"
    #define NAKED        __attribute__((naked))
    #define NAKED_RET    "ret;"
    #define SYSCALL_INST "syscall;"
    #define XCHG_RCX_R10() asm volatile("xchg %rcx, %r10;")
#elif defined(__aarch64__)
    #define SYSCALL_ARG0 "x0"
    #define SYSCALL_ARG1 "x1"
    #define SYSCALL_ARG2 "x2"
    #define SYSCALL_ARG3 "x3"
    #define SYSCALL_ARG4 "x4"
    #define SYSCALL_ARG5 "x5"
    #define SYSCALL_NR   "x8"
    #define SYSCALL_RET  "x0"
    #define NAKED
    #define NAKED_RET
    #define SYSCALL_INST "svc #0;"
    #define XCHG_RCX_R10()
#endif

inline __attribute__((always_inline))
void* alloca(size_t s)
{
    register void* sp asm(SP);
    s += 0xf;
    s &= ~0xf;
    sp -= s;
    return sp;
}
inline __attribute__((always_inline))
size_t strlen(const char* str)
{
    size_t i;
    for (i = 0; str[i]; ++i);
    return i;
}
inline __attribute__((always_inline))
int strcmp(const char* str1, const char* str2)
{
    volatile int r;
    for (size_t i = 0; !(r = (str1[i] - str2[i])) && str1[i] && str2[i]; ++i);
    return r;
}
void* memcpy(void* dest, const void* src, size_t n)
{
    for (volatile size_t i = 0; i < n; ++i)
        ((char*) dest)[i] = ((char*) src)[i];
    return dest;
}
#define ishexdigit(c) \
    (('0' <= (c) && (c) <= '9') || ('a' <= (c) && (c) <= 'f'))
inline __attribute__((always_inline))
int hexvalue(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    else
        return c - 'a' + 0xa;
}
inline __attribute__((always_inline))
unsigned long hex2val(const char* s)
{
    unsigned long ret = 0;

    int lim;
    for (lim = 0; ishexdigit(s[lim]); ++lim);

    int order = 1;
    for (int i = lim - 1; i >= 0; --i)
    {
        ret += hexvalue(s[i]) * order;
        order *= 0x10;
    }

    return ret;
}

inline __attribute__((always_inline))
int mprotect(void* addr, size_t len, int prot)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile void*         a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a2 = prot;
    a1 = len;
    a0 = addr;
    nr = SYS_mprotect;

    // PREVENT FUCKING OPTIMIZATIONS
    asm volatile("" : : "r"(nr), "r"(a0), "r"(a1), "r"(a2));
    asm volatile(SYSCALL_INST);

    return (long) r;
}
inline __attribute__((always_inline))
long lseek(int fd, off_t off, int whence)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a2 = whence;
    a1 = off;
    a0 = fd;
    nr = SYS_lseek;

    asm volatile("" : : "r"(nr), "r"(a0), "r"(a1), "r"(a2));
    asm volatile(SYSCALL_INST);

    return r;
}
inline __attribute__((always_inline))
int openat(int fd, const char* path, int flags, ...)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile const char*   a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a2 = flags;
    a1 = path;
    a0 = fd;
    nr = SYS_openat;

    asm volatile("" : : "r"(nr), "r"(a0), "r"(a1), "r"(a2));
    asm volatile(SYSCALL_INST);

    return r;
}
inline __attribute__((always_inline))
int close(int fd)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a0 asm(SYSCALL_ARG0);
    register volatile unsigned long r  asm(SYSCALL_RET);
    a0 = fd;
    nr = SYS_close;

    asm volatile("" : : "r"(nr), "r"(a0));
    asm volatile(SYSCALL_INST);

    return r;
}
inline __attribute__((always_inline))
void* mremap(void* old_addr, size_t old_sz, size_t new_sz, int flags, ...)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile void*         a0 asm(SYSCALL_ARG0);
    register volatile unsigned long a1 asm(SYSCALL_ARG1);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    register volatile unsigned long a3 asm(SYSCALL_ARG3);
    register void* volatile         r  asm(SYSCALL_RET);
    a0 = old_addr;
    a1 = old_sz;
    a2 = new_sz;
    a3 = flags;
    nr = SYS_mremap;

    asm volatile("" : : "r"(nr), "r"(a0), "r"(a1), "r"(a2), "r"(a3));
    asm volatile(SYSCALL_INST);

    return r;
}
NAKED
int munmap(void* addr, size_t len)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_munmap;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
void* mmap(void* addr, size_t len, int prot, int flag, int fd, off_t off)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    XCHG_RCX_R10();
    nr = SYS_mmap;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
ssize_t read(int fd, void* addr, size_t count)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    nr = SYS_read;
    asm volatile(SYSCALL_INST NAKED_RET);
}
NAKED
int dup2(int fd1, int fd2)
{
    register volatile unsigned long nr asm(SYSCALL_NR);
    register volatile unsigned long a2 asm(SYSCALL_ARG2);
    nr = SYS_dup3;
    a2 = 0;
    asm volatile(SYSCALL_INST NAKED_RET);
}
