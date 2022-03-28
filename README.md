# DDexec
## Context
In Linux in order to run a program it must exist as a file, it must be accessible in some way through the file system hierarchy (this is just how `execve()` works). This file may reside on disk or in ram (tmpfs, memfd) but you need a filepath. This has made very easy to control what is run on a Linux system, it makes easy to detect threats and attacker's tools or to prevent them from trying to execute anything of theirs at all (_e. g._ not allowing unprivileged users to create executable files anywhere).

But this technique is here to change all of this. If you can not start the process you want... then you hijack one already existing.

## Usage
Pipe into the `ddexec.sh` script the base64 of the binary you want to run (**without** newlines). The arguments for the script are the arguments for the program (starting with `argv[0]`).

Here, try this:
```
base64 -w0 /bin/ls | bash ddexec.sh /bin/ls -lA
```

There is also the `ddsc.sh` script that allows you to run binary code directly.
The following is a "Hello world" shellcode.
```
bash ddsc.sh -x <<< "4831c0fec089c7488d3510000000ba0c0000000f054831c089c7b03c0f0548656c6c6f20776f726c640a00"
```
or
```
bash ddsc.sh < <(xxd -ps -r <<< "4831c0fec089c7488d3510000000ba0c0000000f054831c089c7b03c0f0548656c6c6f20776f726c640a00")
```

And yes. It works with meterpreter.

Supported shells are bash, zsh and ash.

Currently **only x86-64** architecture is supported, but you can follow the progress in the [ARM/Aarch64 branch](https://github.com/arget13/DDexec/tree/arm). The shellcode already works on Aarch64, the problem is that the creation of a ROP on this architecture is [tricky](https://github.com/arget13/DDexec/issues/7), especially when you have to implement also the gadget search.

Tested Linux distributions are Debian, Alpine and Arch.

### A little trick
In bash and (surprisingly) ash you may do the following in a shell:
```
$ ddexec()
> {
>    # Paste here the script as is
> }
$ base64 -w0 /bin/ls | ddexec /bin/ls -lA
```

## Dependencies
This script depends on the following tools to work.
```
dd
bash | zsh | ash (busybox)
setarch | linux64 (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
sleep
```

## The technique
If you are able to modify arbitrarily the memory of a process then you can take over it. This can be used to hijack an already existing process and replace it with another program. We can achieve this either by using the `ptrace()` syscall (which requires you to have the ability to execute syscalls or to have gdb available on the system) or, more interestingly, writing to `/proc/$pid/mem`.

The file `/proc/$pid/mem` is a one-to-one mapping of the entire address space of a process (_e. g._ from `0x0000000000000000` to `0x7ffffffffffff000` in x86-64). This means that reading from or writing to this file at an offset `x` is the same as reading from or modifying the contents at the virtual address `x`.

Now, we have four basic problems to face:
- ASLR.
- Executable pages are read-only.
- If we try to read or write to an address not mapped in the address space of the program we will get an I/O error.
- In general only root and the program owner of the file may modify it.

This problems have solutions that, although they are not perfect, are good:
- For ASLR we have the `setarch` utility (on busybox distributions it is `linux64`).
- To make an executable page writable we will need to make a bit of basic exploiting: **ROP**.
- So we need to `lseek()` over the file. From the shell this cannot be done unless using the infamous `dd`.
- Well, we make `dd` exploit itself. This also has the benefit of allowing us to use `/proc/self` instead of having to find the PID of the targetted program.

### In more detail
The steps are relatively easy and do not require any kind of expertise to understand them. Anyone with a basic understanding of exploiting and with some knowledge of the ELF format can follow this.
* Find base address of the libc and the loader. Since there is no ASLR we do not need a memory leak, so this is very easy. It can be done just by running a program without ASLR and looking at its `/proc/$pid/maps`.
* Parse the symbols in the libc looking for the offset of the `read()` and `mprotect()` functions. Now we can obtain their virtual addresses, and therefore craft a very basic `mprotect() + read()` ROP.
* Parse the binary we want to run and the loader to find out what mappings they need. Then craft a "shell"code that will perform, broadly speaking, the same steps that the kernel does upon each call to `execve()`:
    * Create said mappings.
    * Read the binaries into them.
    * Set up permissions.
    * Finally initialize the stack with the arguments for the program and place the auxiliary vector (needed by the loader)
    * Jump into the loader and let it do the rest (load libraries needed by the program).
* Overwrite the `RIP(s)` of some function, preferrably the `write()`'s one, with the ROP. A _retsled_ will make this easier. However we can not write more than a page at a time (4096 bytes), since `dd` makes calls to `write()` of this size maximum. So our ROP is limited to 4096 bytes (which is not bad at all).
* Pass the "shell"code to the stdin of the now hijacked `dd` process (will be `read()` by the ROP and executed).
* Pass the program we want to run to the stdin of the process (will be `read()` by said "shell"code).
* At this point it is up to the loader to load the necessary libraries for our program and jump into it.

Oh, and all of this must be done in s**hell** scripting, or what would be the point?

## Contribute
Well, there are a couple of TODOs. Besides this, you may have noticed that I do not know much about shell scripting (I am more of a C programmer) and I am sure I must have won a decade worth of ["useless use of an echo"](https://porkmail.org/era/unix/award.html) awards and the rest of variants just with a fraction of this project.

- Improve code style and performance.
- Port to another architecture.
- Port to other shells.
- Reduce the amount of dependencies needed, or even detect dynamically if the system has alternatives for a missing one.
- Allow run the program with a non-empty environment.
- Take into account that this can be easily adapted to every program that allows seeking through a file.

You may find useful the project's [wiki](https://github.com/arget13/DDexec/wiki) (which I am still writing).

Anyway, **all contribution is welcome**. Feel free to fork and PR.

## Credit
Recently I have come to know that [Sektor7](https://www.sektor7.net) had already [published](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md) this almost-exact same technique on their blog a few years ago.

Despite this, this technique has been thought and developed by me independently in its entirety. I have also gone much further creating an easy to use implementation and avoiding the `memfd_create() + execve()` technique (which is very noisy). Also, an error committed in their version is to rely on a GOT overwrite, when most of the current compilations of dd are **full RelRO**. Anyway, I hope I will be able to spread the use of this technique much further.

I would like to thank [Carlos Polop](https://github.com/carlospolop), a great pentester and better friend, for making me think about this subject, and for his helpful feedback and interest, oh and the name of the project. I am sure that if you are reading this you have already used his awesome tool [PEASS](https://github.com/carlospolop/PEASS-ng) and found helpful some article in his book [HackTricks](https://book.hacktricks.xyz). Also thank him for helping me with the talk at the [RootedCon 2022](https://rootedcon.com).

## Now what?
This technique can be prevented in several ways.
- Not installing `dd` (maybe even go distroless?).
- Making `dd` executable only by root.
- Using a kernel compiled without support for the `mem` file.
- Check if `dd` calls `mprotect()` with `PROT_EXEC`.

## Questions? Death threats?
Feel free to send me an email to [arget@protonmail.ch](mailto:arget@protonmail.ch).
