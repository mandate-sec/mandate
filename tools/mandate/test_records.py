from pathlib import Path
import json,sys,tempfile,unittest
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
import mandate

class Records(unittest.TestCase):
    def test_lifecycle(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            private,public,record=[root/n for n in ("private","public","record")]
            def run(command,*args):
                argv=["mandate",command,"--trusted-key",str(public),*args]
                if command!="verify": argv+=["--key",str(private)]
                if command!="keygen": argv+=["--file",str(record)]
                with patch.object(sys,"argv",argv),patch("getpass.getpass",return_value="temporary test passphrase"):
                    mandate.main()
            run("keygen")
            self.assertIn(b"ENCRYPTED PRIVATE KEY",private.read_bytes())
            now=datetime.now(timezone.utc)
            expiry=(now+timedelta(days=1)).isoformat()
            run("create","--engagement","local","--targets","localhost","--checks","web_scan","--name","Local","--email","local@example.org","--expires",expiry)
            run("verify")
            grant = root / "approval.json"
            approval = dict(key_fingerprint=json.loads(record.read_text())["authorized_by"]["key_fingerprint"],
                            targets=["LOCALHOST"], checks=["web_scan"], max_concurrency=1, expires=expiry)
            grant.write_text(json.dumps(approval))
            run("verify", "--approval", str(grant))
            for change in ({"targets": ["other.example"]}, {"checks": []}, {"max_concurrency": True},
                           {"key_fingerprint": "other"}, {"expires": now.isoformat()}):
                with self.subTest(change=change):
                    grant.write_text(json.dumps(approval | change))
                    with self.assertRaises(ValueError):
                        run("verify", "--approval", str(grant))
            with self.assertRaises(ValueError): mandate.verify(record,public,now+timedelta(days=2))
            run("renew","--expires",(now+timedelta(days=3)).isoformat())
            run("verify")
            data=json.loads(record.read_text()); data["scope"]["targets"]=["other.example"]
            record.write_text(json.dumps(data))
            with self.assertRaises(mandate.InvalidSignature): run("verify")

if __name__=="__main__":unittest.main()
