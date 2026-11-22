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
            run("create","--engagement","local","--targets","localhost","--checks","web_scan","--name","Local","--email","local@example.org","--expires",expiry,
                "--excluded", "Monitoring.Example,2001:db8::1,auth_bypass")
            run("verify")
            grant = root / "approval.json"
            approval = dict(engagement="local", key_fingerprint=json.loads(record.read_text())["authorized_by"]["key_fingerprint"],
                            targets=["LOCALHOST"], checks=["web_scan"], max_concurrency=1, expires=expiry)
            grant.write_text(json.dumps(approval))
            run("verify", "--approval", str(grant))
            excludes = ["monitoring.example", "2001:0db8:0:0:0:0:0:1/128", "auth_bypass"]
            grant.write_text(json.dumps(approval | {"excluded": excludes}))
            run("verify", "--approval", str(grant))
            grant.write_text(json.dumps(approval | {"excluded": excludes + ["private.example"]}))
            with self.assertRaisesRegex(ValueError, "required exclusion"):
                run("verify", "--approval", str(grant))
            for malformed in ("auth_bypass", [False], ["2001:db8::/064"]):
                grant.write_text(json.dumps(approval | {"excluded": malformed}))
                with self.assertRaises(ValueError):
                    run("verify", "--approval", str(grant))
            grant.write_text(json.dumps(approval))
            # Model a grant read that finishes exactly when the record expires.
            class Clock(datetime):
                @classmethod
                def now(cls, tz):
                    return cls.current.astimezone(tz)

            Clock.current = now + timedelta(hours=1)
            original_check = mandate.check_approval
            def delayed_approval(obj, path):
                original_check(obj, path)
                Clock.current = datetime.fromisoformat(expiry)

            with patch.object(mandate, "datetime", Clock), patch.object(mandate, "check_approval", delayed_approval):
                with self.assertRaisesRegex(ValueError, "validity window"):
                    run("verify", "--approval", str(grant))
            grant.write_text(json.dumps({k: v for k, v in approval.items() if k != "engagement"}))
            with self.assertRaisesRegex(ValueError, "expected fields"):
                run("verify", "--approval", str(grant))
            for change in ({"engagement": "other"}, {"targets": ["other.example"]}, {"checks": []}, {"max_concurrency": True},
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
