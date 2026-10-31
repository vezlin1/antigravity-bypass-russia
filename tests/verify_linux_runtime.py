"""Exercise real Linux DNS setup/rollback in private mount, PID and network namespaces."""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('--cli-fixture', type=Path)
parser.add_argument('--cli-version', help='Expected CLI fixture version (default: pinned Linux CLI)')
parser.add_argument('--resolved-binary', type=Path)
parser.add_argument('--dbus-daemon', type=Path)
parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
args = parser.parse_args()
binary = args.binary.resolve()
if sys.platform != 'linux' or os.geteuid() != 0:
    raise SystemExit('Run as root on Linux; all runtime mutations occur in private namespaces.')
if args.cli_fixture and not args.cli_version:
    pinned=json.loads((Path(__file__).resolve().parent/'upstream-versions.json').read_text())
    args.cli_version=pinned['cli']['linux_amd64']['version']
if not args.inside:
    command=['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc', sys.executable, str(Path(__file__).resolve()), str(binary), '--inside']
    if args.cli_fixture: command.extend(['--cli-fixture',str(args.cli_fixture.resolve()),'--cli-version',args.cli_version])
    if args.resolved_binary: command.extend(['--resolved-binary',str(args.resolved_binary.resolve()),'--dbus-daemon',str(args.dbus_daemon.resolve())])
    subprocess.run(command, check=True, timeout=180)
    raise SystemExit(0)
assert os.getpid() == 1, 'The test must be PID 1 in its private namespace'
subprocess.run(['mount', '--make-rprivate', '/'], check=True)
work = Path(tempfile.mkdtemp(prefix='ag-linux-runtime-'))
shutil.copytree('/etc', work/'etc', symlinks=True)
subprocess.run(['mount', '--bind', str(work/'etc'), '/etc'], check=True)
for directory in ['/var/lib', '/run']:
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', directory], check=True)
for directory in ['/run/lock','/run/shm','/run/user']:
    Path(directory).mkdir(exist_ok=True)
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
home = work/'home'
home.mkdir()
os.chown(home, 65534, 65534)
passwd = Path('/etc/passwd')
passwd.write_text('\n'.join(':'.join(fields[:5]+[str(home)]+fields[6:]) if fields[0]=='nobody' else ':'.join(fields) for fields in (line.split(':') for line in passwd.read_text().splitlines()))+'\n')
resolv = Path('/etc/resolv.conf')
if resolv.is_symlink(): resolv.unlink()
original = b'# private resolver\nsearch corp.test\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n'
resolv.write_bytes(original)
hosts = Path('/etc/hosts')
original_hosts = hosts.read_bytes()
domains = ['daily-cloudcode-pa.googleapis.com', 'cloudcode-pa.googleapis.com', 'generativelanguage.googleapis.com', 'aicode.googleapis.com']

def dns_server(address, smart, scope=0):
    ipv6=':' in address
    server = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address,53,0,scope) if ipv6 else (address,53))
    def serve():
        while True:
            data, peer = server.recvfrom(65535)
            end = 12
            while data[end]: end += data[end]+1
            end += 1
            qtype = struct.unpack_from('!H', data, end)[0]
            question = data[12:end+4]
            answer = b''
            if qtype in [1, 28]:
                ip = ('127.0.0.2' if smart else '192.0.2.123') if qtype == 1 else '2001:db8::123'
                raw = ipaddress.ip_address(ip).packed
                answer = b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,60,len(raw))+raw
            reply = data[:2]+struct.pack('!HHHHH',0x8180,1,bool(answer),0,0)+question+answer
            server.sendto(reply,peer)
    threading.Thread(target=serve, daemon=True).start()

dns_server('127.0.0.1', False)
dns_server('127.0.0.2', True)
cert, key = work/'cert.pem', work/'key.pem'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=Antigravity isolated test','-addext','subjectAltName='+','.join('DNS:'+d for d in domains)], check=True, capture_output=True)
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401); self.send_header('Content-Length','0'); self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *args): pass
server = http.server.ThreadingHTTPServer(('127.0.0.2',443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert,key)
server.socket = context.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
config = home/'.config/AntigravityBypass/network'
config.mkdir(parents=True)
(config/'network.json').write_text(json.dumps({'doh':[], 'extra_udp':[{'name':'fixture','addresses':['127.0.0.2']}], 'disabled_providers':['geohide.ru'], 'provider_order':['fixture'], 'watch_region_errors':False,'log_roots':[]}))
environment = dict(os.environ, SUDO_UID='65534', SUDO_USER='nobody', HOME=str(home), SSL_CERT_FILE=str(cert), SSL_CERT_DIR=str(work/'empty-certs'))

def run(*arguments, success=True):
    result = subprocess.run([str(binary), *arguments], env=environment, capture_output=True, text=True, timeout=70)
    if success and result.returncode:
        for path in Path('/var/lib/antigravity_bypass_russia').glob('*.log'):
            print(path.name,path.read_text()[-5000:],flush=True)
    assert (result.returncode==0)==success, (arguments,result.returncode,result.stdout,result.stderr)
    return result

def query(name, qtype=1, tcp=False):
    packet = struct.pack('!HHHHHH',42,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',qtype,1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.settimeout(5)
    with sock:
        sock.connect(('127.0.0.55',53))
        if tcp:
            sock.sendall(struct.pack('!H',len(packet))+packet)
            length = struct.unpack('!H',sock.recv(2))[0]
            reply = b''
            while len(reply)<length: reply += sock.recv(length-len(reply))
            return reply
        sock.send(packet)
        return sock.recv(65535)

run('dns')
applied = resolv.read_bytes()
assert b'nameserver 127.0.0.55' in applied and b'search corp.test' in applied
assert b'127.0.0.2 gemini.google.com' not in hosts.read_bytes(), 'Browser DNS must use the resolver, not incidental hosts pins'
assert query('gemini.google.com').endswith(socket.inet_aton('127.0.0.2'))
assert query('api.aistudio.google.com').endswith(socket.inet_aton('127.0.0.2'))
assert query('private.corp.test').endswith(socket.inet_aton('192.0.2.123'))
assert query('private.corp.test',28).endswith(ipaddress.ip_address('2001:db8::123').packed)
assert query('private.corp.test',tcp=True).endswith(socket.inet_aton('192.0.2.123'))
assert {x[4][0] for x in socket.getaddrinfo('gemini.google.com',443,socket.AF_INET)}=={'127.0.0.2'}
print('PASS: real Linux setup, system resolver, browser suffixes, private DNS, AAAA and TCP',flush=True)
run('dns')
assert resolv.read_bytes()==applied
print('PASS: repeated setup restarts the standalone worker without systemd',flush=True)
resolv.write_bytes(applied+b'# changed by another program\n')
run('rollback',success=False)
assert query('gemini.google.com').endswith(socket.inet_aton('127.0.0.2'))
assert resolv.read_bytes().endswith(b'# changed by another program\n')
resolv.write_bytes(applied)
run('rollback')
assert resolv.read_bytes()==original and hosts.read_bytes()==original_hosts
assert not Path('/var/lib/antigravity_bypass_russia/linux-dns.json').exists()
run('rollback')
print('PASS: concurrent DNS edits block teardown; exact rollback is repeatable',flush=True)
if args.cli_fixture:
    cli=work/'agy'
    shutil.copyfile(args.cli_fixture,cli); cli.chmod(0o755)
    stock=hashlib.sha256(cli.read_bytes()).digest()
    fake=work/'failed-lsof';fake.write_text('#!/bin/sh\nexit 2\n');fake.chmod(0o755)
    lsof=shutil.which('lsof')
    subprocess.run(['mount','--bind',str(fake),lsof],check=True)
    run('patch-files',str(cli),success=False)
    assert hashlib.sha256(cli.read_bytes()).digest()==stock
    subprocess.run(['umount',lsof],check=True)
    real_lsof=work/'real-lsof'
    shutil.copyfile(lsof,real_lsof);real_lsof.chmod(0o755)
    fake.write_text('#!/missing-lsof-interpreter\n')
    subprocess.run(['mount','--bind',str(fake),lsof],check=True)
    run('patch-files',str(cli),success=False)
    assert hashlib.sha256(cli.read_bytes()).digest()==stock
    subprocess.run(['umount',lsof],check=True)
    fake.write_text('#!/bin/sh\necho "lsof: WARNING: can\'t stat() ext4 file system /opt" >&2\nexit 1\n')
    subprocess.run(['mount','--bind',str(fake),lsof],check=True)
    run('patch-files',str(cli),success=False)
    assert hashlib.sha256(cli.read_bytes()).digest()==stock
    subprocess.run(['umount',lsof],check=True)
    fake.write_text('#!/bin/sh\necho "lsof: WARNING: can\'t stat() fuse.portal file system /run/user/1000/doc" >&2\necho "    Output information may be incomplete." >&2\necho "lsof: WARNING: can\'t stat() fuse.gvfsd-fuse file system /run/user/1000/gvfs" >&2\necho "    Output information may be incomplete." >&2\nexec "'+str(real_lsof)+'" "$@"\n')
    subprocess.run(['mount','--bind',str(fake),lsof],check=True)
    with cli.open('rb'):
        run('patch-files',str(cli),success=False)
        assert hashlib.sha256(cli.read_bytes()).digest()==stock
    run('patch-files',str(cli))
    assert hashlib.sha256(cli.read_bytes()).digest()!=stock
    version=subprocess.run([str(cli),'--version'],env=environment,capture_output=True,text=True,timeout=20)
    assert version.returncode==0 and args.cli_version in version.stdout,version
    run('patch-files',str(cli))
    run('rollback',str(cli))
    assert hashlib.sha256(cli.read_bytes()).digest()==stock
    subprocess.run(['umount',lsof],check=True)
    print('PASS: missing/failed lsof and unknown warnings block writes; unrelated desktop FUSE warnings allow patching but preserve real holders',flush=True)
    print(f'PASS: native CLI {args.cli_version} patch, execution, repeat patch and exact rollback with desktop FUSE warnings',flush=True)
if args.resolved_binary:
    with Path('/etc/passwd').open('a') as file: file.write('systemd-resolve:x:991:991::/run/systemd/resolve:/usr/sbin/nologin\n')
    with Path('/etc/group').open('a') as file: file.write('systemd-resolve:x:991:\n')
    Path('/run/systemd/resolve').mkdir(parents=True,exist_ok=True)
    Path('/run/systemd/system').mkdir(parents=True,exist_ok=True)
    os.chown('/run/systemd/resolve',991,991)
    for directory in ['bin-upper','bin-work']: (work/directory).mkdir()
    subprocess.run(['mount','-t','overlay','overlay','-o',f'lowerdir=/usr/bin,upperdir={work}/bin-upper,workdir={work}/bin-work','/usr/bin'],check=True)
    shutil.copyfile(args.resolved_binary.parents[2]/'usr/bin/resolvectl','/usr/bin/resolvectl')
    Path('/usr/bin/resolvectl').chmod(0o755)
    bus_config=work/'bus.conf'
    Path('/run/dbus').mkdir()
    bus_config.write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    bus_log=(work/'bus.log').open('w')
    bus=subprocess.Popen([str(args.dbus_daemon),'--nofork','--config-file='+str(bus_config)],stdout=bus_log,stderr=bus_log)
    import time
    for _ in range(50):
        if Path('/run/dbus/system_bus_socket').exists(): break
        time.sleep(.1)
    Path('/etc/systemd/resolved.conf').write_text('[Resolve]\nDNSSEC=no\nDNSStubListener=yes\n')
    resolved_log=(work/'resolved.log').open('w')
    resolved=subprocess.Popen([str(args.resolved_binary)],env=dict(os.environ,SYSTEMD_LOG_LEVEL='debug',DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/dbus/system_bus_socket'),stdout=resolved_log,stderr=resolved_log)
    for _ in range(50):
        result=subprocess.run(['resolvectl','status'],capture_output=True)
        if result.returncode==0: break
        time.sleep(.1)
    assert result.returncode==0,(result.stdout.decode(),result.stderr.decode(),(work/'bus.log').read_text(),(work/'resolved.log').read_text())
    subprocess.run(['ip','link','add','agtest0','type','dummy'],check=True)
    subprocess.run(['ip','addr','add','198.51.100.1/24','dev','agtest0'],check=True)
    subprocess.run(['ip','link','set','agtest0','up'],check=True)
    subprocess.run(['resolvectl','dns','agtest0','127.0.0.1'],check=True)
    subprocess.run(['resolvectl','domain','agtest0','corp.test'],check=True)
    plan=Path('/var/lib/antigravity_bypass_russia/linux-dns.json')
    plan.write_text(json.dumps({'servers':['127.0.0.1'],'backend':{'Resolved':{'interface':'agtest0','domains':['corp.test'],'default_route':False}}}))
    worker=subprocess.Popen([str(binary),'--dns-forwarder'],env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    time.sleep(.3)
    run('--linux-dns-apply')
    result=subprocess.run(['resolvectl','query','-4','gemini.google.com'],capture_output=True,text=True,timeout=12)
    assert result.returncode==0 and '127.0.0.2' in result.stdout,(result.stdout,result.stderr,(work/'resolved.log').read_text())
    run('rollback')
    assert '127.0.0.1' in subprocess.check_output(['resolvectl','dns','agtest0'],text=True)
    assert subprocess.check_output(['resolvectl','domain','agtest0'],text=True).strip().endswith('corp.test')
    subprocess.run(['ip','-6','addr','add','fe80::53/64','dev','agtest0','nodad'],check=True)
    dns_server('fe80::53',False,socket.if_nametoindex('agtest0'))
    subprocess.run(['resolvectl','dns','agtest0','fe80::53'],check=True)
    plan.write_text(json.dumps({'servers':['fe80::53'],'backend':{'Resolved':{'interface':'agtest0','domains':['corp.test'],'default_route':False}}}))
    run('--linux-dns-apply')
    assert query('private.corp.test').endswith(socket.inet_aton('192.0.2.123')), 'Original link-local IPv6 DNS must retain its interface scope'
    run('rollback')
    assert 'fe80::53' in subprocess.check_output(['resolvectl','dns','agtest0'],text=True)
    print('PASS: original link-local IPv6 DNS remains reachable through its interface',flush=True)
    worker.terminate();worker.wait(timeout=5)
    Path('/run/systemd/system').rmdir()
    subprocess.run(['resolvectl','dns','agtest0','127.0.0.1'],check=True)
    subprocess.run(['resolvectl','domain','agtest0',''],check=True)
    subprocess.run(['ip','route','add','8.8.8.8/32','dev','agtest0'],check=True)
    dns_server('198.51.100.1',True)
    network=json.loads((config/'network.json').read_text())
    network['extra_udp'][0]['addresses']=['198.51.100.1']
    (config/'network.json').write_text(json.dumps(network))
    resolv.write_text('nameserver 127.0.0.53\n')
    run('dns')
    prepared=json.loads(plan.read_text())
    assert prepared['backend']['Resolved']['interface']=='agtest0'
    assert prepared['backend']['Resolved']['domains']==[]
    assert prepared['backend']['Resolved']['default_route'] is True
    assert {x[4][0] for x in socket.getaddrinfo('fresh.aistudio.google.com',443,socket.AF_INET)}=={'127.0.0.2'}
    ordinary=subprocess.run(['resolvectl','query','-4','public.example.com'],capture_output=True,text=True,timeout=12)
    assert ordinary.returncode==0 and '192.0.2.123' in ordinary.stdout,(ordinary.stdout,ordinary.stderr)
    run('dns')
    assert json.loads(plan.read_text())==prepared
    run('rollback')
    assert subprocess.check_output(['resolvectl','domain','agtest0'],text=True).strip().endswith(':')
    resolv.write_bytes(original)
    print('PASS: full systemd-resolved setup detects an empty-domain interface and keeps ordinary DNS available',flush=True)
    resolved.terminate();resolved.wait(timeout=5)
    bus.terminate();bus.wait(timeout=5)
    print('PASS: real systemd-resolved routing, per-link settings and exact DNS/domain rollback',flush=True)

# A present manager failing to register the unit must not report success or
# launch an unregistered replacement worker.
Path('/run/systemd/system').mkdir(parents=True,exist_ok=True)
failed=work/'failed-systemctl';failed.write_text('#!/bin/sh\necho test-manager-failure >&2\nexit 2\n');failed.chmod(0o755)
subprocess.run(['mount','--bind',str(failed),shutil.which('systemctl')],check=True)
run('dns',success=False)
assert resolv.read_bytes()==original
subprocess.run(['systemd-analyze','verify','--man=no','/etc/systemd/system/antigravity-bypass-russia.service'],check=True,capture_output=True)
print('PASS: systemd failure is reported without switching DNS or starting a fallback worker',flush=True)
