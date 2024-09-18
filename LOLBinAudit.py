import os
import csv
import subprocess
import argparse

winning_bins = []
  
def main():
    #parser = argparse.ArgumentParser(description = "Enter a file you want to process")
    #parser.add_argument("file", type=str, help = "Argument for file to read")

    #args = parser.parse_args()

    system_bins = fillCsv('lolbin-database.csv')
   
    startLOL(system_bins)

    return 0

def fillCsv(file):
    system_bins = {}

    with open(file, mode = 'r') as csvfile:
        reader = csv.reader(csvfile)

        for bin in reader:
            name = bin[0]
            try:
                result = subprocess.Popen([bin[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                system_bins[name] = 1
            except:
                system_bins[name] = 0

    return system_bins



#Decision tree for what bin function to call
def startLOL(bins, file):
    for bin in bins:
        if(check_value(bin, file)):
            winning_bins.append(bin)

 

#Bin function
def sevenZ(file):
    result = subprocess.Popen(["7z", "a", "-ttar", "-an", "-s ", lfile, " | ", "7z", "e", "-ttar", "-si", "-so"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    


def check_value(bin, file):
    return {
        "7z": sevenZ(file)
        "aa-exec":  
        "ab":  
        "agetty":  
        "alpine":  
        "ansible-playbook":  
        "ansible-test":  
        "aoss":  
        "apache2ctl":  
        "apt-get":  
        "apt":  
        "ar":  
        "aria2c":  
        "arj":  
        "arp":  
        "as":  
        "ascii-xfr":  
        "ascii85":  
        "ash":  
        "aspell":  
        "at":  
        "atobm":  
        "awk":  
        "aws":  
        "base32":  
        "base58":  
        "base64":  
        "basenc":  
        "basez":  
        "bash":  
        "batcat":  
        "bc":  
        "bconsole":  
        "bpftrace":  
        "bridge":  
        "bundle":  
        "bundler":  
        "bustctl":  
        "busybox":  
        "byebug":  
        "bzip2":  
        "c89":  
        "c99":  
        "cabal":  
        "cancel":  
        "capsh":  
        "cat":  
        "cdist":  
        "certbot":  
        "check_by_ssh":  
        "check_cups":  
        "check_log":  
        "check_memory":  
        "check_raid":  
        "check_ssl_cert":  
        "check_statusfile":  
        "chmod":  
        "choom":  
        "chown":  
        "chroot":  
        "clamscan":  
        "cmp":  
        "cobc":  
        "column":  
        "comm":  
        "composer":  
        "cowsay":  
        "cowthink":  
        "cp":  
        "cpan":  
        "cpio":  
        "cpuliit":  
        "crash":  
        "crontab":  
        "csh":  
        "csplit":  
        "csvtool":  
        "cupsfilter":  
        "curl":  
        "cut":  
        "dash":  
        "date":  
        "dc":  
        "dd":  
        "debugfs":  
        "dialog":  
        "diff":  
        "dig":  
        "distcc":  
        "dmesg":  
        "dmidecode":  
        "dmsetup":  
        "dnf":  
        "docker":  
        "dos2unix":  
        "dosbox":  
        "dotnet":  
        "dpkg":  
        "dstat":  
        "dvips":  
        "easy_install":  
        "eb":  
        "ed":  
        "efax":  
        "elvish":  
        "emacs":  
        "enscript":  
        "env":  
        "eqn":  
        "espeak":  
        "ex":  
        "exiftool":  
        "expand":  
        "expect":  
        "facter":  
        "file":  
        "find":  
        "finger":  
        "fish":  
        "flock":  
        "fmt":  
        "fold":  
        "fping":  
        "ftp":  
        "gawk":  
        "gcc":  
        "gcloud":  
        "gcore":  
        "gdb":  
        "gem":  
        "genie":  
        "genisoimage":  
        "ghc":  
        "ghci":  
        "gimp":  
        "ginsh":  
        "git":  
        "grc":  
        "grep":  
        "gtester":  
        "gzip":  
        "hd":  
        "head":  
        "hexdump":  
        "highlight":  
        "hping3":  
        "iconv":  
        "iftop":  
        "install":  
        "ionice":  
        "ip":  
        "irb":  
        "ispell":  
        "jjs":  
        "joe":  
        "join":  
        "journalctl":  
        "jg":  
        "jrunscript":  
        "jtag":  
        "julia":  
        "knife":  
        "ksh":  
        "ksshell":  
        "ksu":  
        "kubectl":  
        "latex":  
        "latexmk":  
        "ld.so":  
        "ldconfig":  
        "less":  
        "lftp":  
        "links":  
        "ln":  
        "loginctl":  
        "logsave":  
        "look":  
        "lp":  
        "ltrace":  
        "lua":  
        "lualatex":  
        "luatex":  
        "lwp-download":  
        "lwp-request":  
        "mail":  
        "make":  
        "man":  
        "mawk":  
        "minicom":  
        "more":  
        "mosquitto":  
        "mount":  
        "msfconsole":  
        "msgattrib":  
        "msgcat":  
        "msgconv":  
        "msgfilter":  
        "msgmerge":  
        "msguniq":  
        "mtr":  
        "multitime":  
        "mv":  
        "mysql":  
        "nano":  
        "nasm":  
        "nawk":  
        "nc":  
        "ncdu":  
        "ncftp":  
        "neofetch":  
        "nft":  
        "nice":  
        "nl":  
        "nm":  
        "nmap":  
        "node":  
        "nohup":  
        "npm":  
        "nroff":  
        "nsenter":  
        "ntpdate":  
        "octave":  
        "od":  
        "openssl":  
        "openvpn":  
        "openvt":  
        "opkg":  
        "pandoc":  
        "paste":  
        "pax":  
        "pdb":  
        "pdflatex":  
        "pdftex":  
        "perf":  
        "perl":  
        "perlbug":  
        "pexec":  
        "pg":  
        "php":  
        "pic":  
        "pico":  
        "pidstat":  
        "pip":  
        "pkexec":  
        "pkg":  
        "posh":  
        "pr":  
        "pry":  
        "psftp":  
        "psql":  
        "ptx":  
        "puppet":  
        "pwsh":  
        "python":  
        "rake":  
        "rc":  
        "readelf":  
        "red":  
        "redcarpet":  
        "redis":  
        "restic":  
        "rev":  
        "relogin":  
        "rlwrap":  
        "rpm":  
        "rpmdb":  
        "rpmquery":  
        "rpmverify":  
        "rsync":  
        "rtorrent":  
        "ruby":  
        "run-mailcap":  
        "run-parts":  
        "runscript":  
        "rview":  
        "rvim":  
        "sash":  
        "scanmem":  
        "scp":  
        "screen":  
        "script":  
        "scrot":  
        "sed":  
        "service":  
        "setarch":  
        "setfacl":  
        "setlock":  
        "sftp":  
        "sg":  
        "shuf":  
        "slsh":  
        "smbclient":  
        "snap":  
        "socat":  
        "socket":  
        "soelim":  
        "softlimit":  
        "sort":  
        "split":  
        "sqlite3":  
        "sqlmap":  
        "ss":  
        "ssh-agent":  
        "ssh-keygen":  
        "ssh-keyscan":  
        "ssh":  
        "sshpas":  
        "start-stop-daemon":  
        "stdbuf":  
        "strace":  
        "strings":  
        "su":  
        "sudo":  
        "sysctl":  
        "systemctl":  
        "systemd-resolve":  
        "tac":  
        "tail":  
        "tar":  
        "task":  
        "tasket":  
        "tasksh":  
        "tbl":  
        "tclsh":  
        "tcpdump":  
        "tdbtool":  
        "tee":  
        "telnet":  
        "terraform":  
        "tex":  
        "tftp":  
        "tic":  
        "time":  
        "timedatectl":  
        "timeout":  
        "tmate":  
        "tmux":  
        "top":  
        "torify":  
        "torsocks":  
        "troff":  
        "tshark":  
        "ul":  
        "unexpand":  
        "uniq":  
        "unshare":  
        "unsquashfs":  
        "unzip":  
        "update-alternatives":  
        "uudecode":  
        "uuencode":  
        "vagrant":  
        "valgrind":  
        "varnishncsa":  
        "vi":  
        "view":  
        "vigr":  
        "vim":  
        "vimdiff":  
        "vipw":  
        "virsh":  
        "volatility":  
        "w3m":  
        "wall":  
        "watch":  
        "wc":  
        "wget":  
        "whiptail":  
        "whois":  
        "wireshark":  
        "wish":  
        "xargs":  
        "xdg-user-dir":  
        "xdotool":  
        "xelatex":  
        "xetex":  
        "xmodmap":  
        "xmore":  
        "xpad":  
        "xxd":  
        "xz":  
        "yarn":  
        "yash":  
        "yelp":  
        "yum":  
        "zathura":  
        "zip":  
        "zsh":  
        "zsoelim":  
        "zypper":  
    }.get(val, default)()

if __name__ == "__main__":
    main()
