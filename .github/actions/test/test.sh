#!/bin/sh

# Usage: `bash test.sh` (only supported shell for this script is bash)

# TODO
# Add function equal with color for report

exit_status=0

shellcode_base64="4831ff5766ffc748b86f20776f726c640a50b848656c6c48c1e02050488"\
"9e64883c6044889f84889c2b20c0f054831c04889c7b03c0f05"
shellcode_binary=$(printf "%s" "$shellcode_base64" | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')

equal(){
    : 'Helper function
      Ex: equal 0 0 "yes it works"
    '
    local msg=''
    if [ "$1" = "$2" ]; then
      msg="\e[32mSUCCESS: $3\e[0m: (got '$1')"
    else
      exit_status=1
      msg="\e[31mERROR  : $3\e[0m: (expected '$1' and got '$2')"
    fi
    echo -e "$msg"
}

equal 0 0 "Testing equal function primitive"

# DDexec echo
ret=$(base64 -w0 "$(which echo)" |\
     "$1" ddexec.sh echo -n asd qwerty "" zxcvb " fdsa gf")
equal "$(echo -n asd qwerty "" zxcvb " fdsa gf")" "$ret" "bash + ddexec, test 1"

# DDsc shellcode
ret=$(echo $shellcode_base64 | "$1" ddsc.sh -x)
equal "Hello world" "$ret" "bash + ddsc, test 1"

# DDsc shellcode bin
ret=$(printf "$shellcode_binary" | "$1" ./ddsc.sh)
equal "Hello world" "$ret" "bash + ddsc, test 2"

exit "$exit_status"
