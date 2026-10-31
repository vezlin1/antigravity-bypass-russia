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
        env=dict(os.environ,AG_BYPASS_INSTALL_DIR=prefix.as_posix(),AG_INSTALL_URL_LOG=log.as_posix())
        # A Windows drive colon is a PATH separator in Bash. Normalize paths
        # explicitly so mock tools also work when checkout and TEMP use different drives.
        invocation='''
tools="$1"
installer="$2"
if command -v cygpath >/dev/null 2>&1; then
  tools="$(cygpath -u -- "$tools")"
  installer="$(cygpath -u -- "$installer")"
  export AG_BYPASS_INSTALL_DIR="$(cygpath -u -- "$AG_BYPASS_INSTALL_DIR")"
  export AG_INSTALL_URL_LOG="$(cygpath -u -- "$AG_INSTALL_URL_LOG")"
fi
export PATH="$tools:$PATH"
exec bash "$installer"
'''
        result=subprocess.run([bash,'-c',invocation,'installer-test',tools.as_posix(),(root/'scripts/install.sh').as_posix()],env=env,capture_output=True,text=True,timeout=15)
        assert result.returncode==0,(result.stdout,result.stderr)
        assert log.read_text().strip()=='https://github.com/vezlin1/antigravity-bypass-russia/releases/latest/download/'+asset
        assert (prefix/'antigravity-bypass-russia').is_file() and (prefix/'ag-bypass').exists()
        print('PASS: installer',system,arch,asset)
