"""Verify Mandate's recorded base commit from the local Git object database."""
import hashlib
import subprocess
import sys


BASE = "fd6376ca392e9eed093f4e627138f0003223579d"
DIGEST = "8c2e045c31d148405fc8782b287c44532c5a9b37ba2696f7419fe5b6574cc73c"


def main():
    git = ["git", "--no-replace-objects"]
    content = subprocess.check_output([*git, "cat-file", "commit", BASE])
    header = b"commit " + str(len(content)).encode("ascii") + b"\0"
    digest = hashlib.sha256(header + content).hexdigest()
    if digest != DIGEST:
        sys.exit("Base commit checksum mismatch")
    subprocess.run([*git, "merge-base", "--is-ancestor", BASE, "HEAD"], check=True)
    print(f"Verified base {BASE}\nCommit object SHA-256 {digest}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("Verification requires Git and checkout history connecting HEAD to the recorded base.")
