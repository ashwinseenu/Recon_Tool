import subprocess, pathlib, pytest

SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "install.sh"

CASES = {
 "debian12": ('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"', "debian", True),
 "debian10": ('ID=debian\nVERSION_ID="10"', "debian", False),
 "ubuntu2204": ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"', "debian", True),
 "ubuntu2004": ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="20.04"', "debian", False),
 "ubuntu2404": ('ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"', "debian", True),
 "rhel9": ('ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.4"', "rhel", True),
 "rhel8": ('ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="8.10"', "rhel", True),
 "rhel7": ('ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="7.9"', "rhel", False),
 "rocky9": ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.3"', "rhel", True),
 "alma9": ('ID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.2"', "rhel", True),
 "centos-stream9": ('ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="9"', "rhel", True),
 "kali": ('ID=kali\nID_LIKE=debian\nVERSION_ID="2024.4"', "debian", True),
 "arch": ('ID=arch', "unsupported", False),
 "alpine": ('ID=alpine\nVERSION_ID=3.19', "unsupported", False),
}


def run(osr, tmp_path):
    f = tmp_path / "os-release"; f.write_text(osr + "\n")
    script = f'''set -e; export RF_SOURCE_ONLY=1 RF_OS_RELEASE={f}; . {SCRIPT}
IFS='|' read -r id like ver pretty <<<"$(detect_distro)"
fam=$(family_of "$id" "$like"); echo "$fam"; check_supported "$fam" "$id" "$ver"'''
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


@pytest.mark.parametrize("name", CASES)
def test_distro(name, tmp_path):
    osr, fam, ok = CASES[name]
    r = run(osr, tmp_path)
    assert r.stdout.strip().splitlines()[0] == fam
    assert (r.returncode == 0) == ok, r.stderr


def test_syntax():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0
