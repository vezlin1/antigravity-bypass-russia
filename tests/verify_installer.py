"""Check real installer selection using a fake downloader and a disposable prefix."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
bash = str(Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/bin/bash.exe') if os.name=='nt' else shutil.which('bash')
with tempfile.TemporaryDirectory(prefix='ag-installer-') as temporary:
    folder=Path(temporary); tools=folder/'tools';tools.mkdir()
    for system,arch,asset in [('Linux','x86_64','antigravity-bypass-russia-linux-x64'),('Linux','aarch64','antigravity-bypass-russia-linux-arm64'),('Darwin','arm64','unlock_and_restore.sh'),('Darwin','x86_64','unlock_and_restore.sh')]:
        (tools/'uname').write_text(f'#!/bin/sh\ncase "$1" in -s) echo {system};; -m) echo {arch};; esac\n',newline='\n')
        (tools/'curl').write_text('#!/bin/sh\nprintf "%s\\n" "$2" > "$AG_INSTALL_URL_LOG"\nprintf "#!/bin/sh\\nexit 0\\n" > "$4"\n',newline='\n')
        for path in tools.iterdir():path.chmod(0o755)
        prefix=folder/('installed-'+system+'-'+arch);log=folder/'url.log'
        env=dict(os.environ,AG_BYPASS_INSTALL_DIR=str(prefix),AG_INSTALL_URL_LOG=str(log))
        # Set PATH inside Bash so Git Bash receives POSIX rather than Windows separators.
        result=subprocess.run([bash,'-c','export PATH="$1:$PATH"; bash "$2"','installer-test',str(tools),str(root/'scripts/install.sh')],env=env,capture_output=True,text=True,timeout=15)
        assert result.returncode==0,(result.stdout,result.stderr)
        assert log.read_text().strip()=='https://github.com/vezlin1/antigravity-bypass-russia/releases/latest/download/'+asset
        assert (prefix/'antigravity-bypass-russia').is_file() and (prefix/'ag-bypass').exists()
        print('PASS: installer',system,arch,asset)
