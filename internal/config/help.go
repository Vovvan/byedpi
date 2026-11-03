package config

const HelpText = `    -i, --ip <ip>             Listening IP, default 0.0.0.0
    -p, --port <num>          Listening port, default 1080
    -D, --daemon              Daemonize
    -w, --pidfile <filename>  Write PID to file
    -E, --transparent         Transparent proxy mode
    -c, --max-conn <count>    Connection count limit, default 512
    -N, --no-domain           Deny domain resolving
    -U, --no-udp              Deny UDP association
    -I, --conn-ip <ip>        Connection bound IP, default ::
    -b, --buf-size <size>     Buffer size, default 16384
    -x, --debug <level>       Print logs, 0, 1 or 2
    -g, --def-ttl <num>       TTL for all outgoing connections
    -F, --tfo                 Enable TCP Fast Open
    -T, --tcp-timeout <s[:b]> Set TCP_USER_TIMEOUT option
    -W, --tls-timeout <s:c:b> Set TLS timeout
    -A, --auto <t,r,s,n,c>    Try desync params after this option
    -L, --auto-mode <s,o,n>   Mode: swop,onreconn,noreconn
    -y, --cache-file <path|-> Dump cache to file or stdout
    -u, --cache-ttl <sec>     Lifetime of cached desync params for IP
    -K, --proto <t,h,u,i>     Protocol whitelist: tls,http,udp,ipv4
    -H, --hosts <file|:str>   Hosts whitelist, filename or :string
    -j, --ipset <file|:str>   IP whitelist
    -V, --pf <port[-portr]>   Ports range whitelist
    -R, --round <num[-numr]>  Number of request to which desync will be applied
    -s, --split <pos_t>       Position format: offset[:repeats:skip][+flag1[flag2]]
                              Flags: +s - SNI offset, +h - HTTP host offset, +n - null
                              Additional flags: +e - end, +m - middle
    -d, --disorder <pos_t>    Split and send reverse order
    -o, --oob <pos_t>         Split and send as OOB data
    -q, --disoob <pos_t>      Split and send reverse order as OOB data
    -f, --fake <pos_t>        Split and send fake packet
    -S, --md5sig              Add MD5 Signature option for fake packets
    -n, --fake-sni <str>      Change SNI in fake
                              Replaced: ? - rand let, # - rand num, * - rand let/num
    -t, --ttl <num>           TTL of fake packets, default 8
    -O, --fake-offset <pos_t> Fake data start offset
    -l, --fake-data <f|:str>  Set custom fake packet
    -Q, --fake-tls-mod <flag> Modify fake TLS CH: rand,orig,msize=<int>
    -e, --oob-data <char>     Set custom OOB data
    -M, --mod-http <h,d,r>    Modify HTTP: hcsmix,dcsmix,rmspace
    -r, --tlsrec <pos_t>      Make TLS record at position
    -m, --tlsminor <ver>      Change minor version of TLS
    -a, --udp-fake <count>    UDP fakes count, default 0
    -Y, --drop-sack           Drop packets with SACK extension
`
