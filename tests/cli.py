#!/usr/bin/env python3
"""Exercise the real Rust CLI against a running gateway, including web-code approval."""
import json,os,stat,subprocess,time,unittest
from pathlib import Path
from management import Management as _Management
BINARY=os.environ.get('ZNTIL_CLI_BINARY',str(Path(__file__).resolve().parents[1]/'target/release/zntilctl'))
class CLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):_Management.setUpClass()
    @classmethod
    def tearDownClass(cls):_Management.tearDownClass()
    def setUp(self):
        self.f=_Management('test_console_assets_and_cache_policy');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.login();self.credentials=Path(self.f.directory)/'cli/credentials.json'
        self.env={**os.environ,'ZNTIL_GATEWAY':f'http://127.0.0.1:{self.f.p.port}','ZNTIL_CREDENTIALS_FILE':str(self.credentials)}
        self.env.pop('ZNTIL_TOKEN',None)
    def cli(self,*args,ok=True):
        r=subprocess.run([BINARY,*args],env=self.env,capture_output=True,text=True,timeout=20)
        if ok:self.assertEqual(r.returncode,0,r.stderr)
        else:self.assertNotEqual(r.returncode,0)
        return json.loads(r.stdout if ok else r.stderr)
    def login(self,read_only=False):
        args=[BINARY,'auth','login','--no-browser','--name','CLI integration agent']
        if read_only:args.append('--read-only')
        log=Path(self.f.directory)/'cli-login.log'
        with log.open('w') as err:
            p=subprocess.Popen(args,env=self.env,stdout=subprocess.PIPE,stderr=err,text=True)
            self.addCleanup(lambda:p.kill() if p.poll() is None else None)
            deadline=time.monotonic()+10;pending=[]
            while time.monotonic()<deadline:
                pending=self.f.api('devices')[1]['pending']
                if pending:break
                time.sleep(.05)
            self.assertTrue(pending)
            self.assertEqual(self.f.api('device/approve','POST',{'user_code':pending[0]['user_code'],'approve':True})[0],200)
            stdout,_=p.communicate(timeout=15)
        self.assertEqual(p.returncode,0,log.read_text());result=json.loads(stdout)
        saved=json.loads(self.credentials.read_text())
        self.assertNotIn(saved['token'],stdout+log.read_text());self.assertNotIn(self.f.key,self.credentials.read_text())
        self.assertEqual(stat.S_IMODE(self.credentials.stat().st_mode),0o600)
        return result,saved
    def test_setup_rules_dry_run_revision_conflict_and_logout(self):
        login,saved=self.login();self.assertEqual(login['scope'],'write')
        self.cli('servers','upsert','--id','cli-origin','--host','127.0.0.1','--port',str(self.f.origins[0].server_port))
        self.cli('proxies','upsert','--id','cli-proxy','--server','cli-origin','--domain','cli.test')
        self.cli('rules','upsert','--proxy','cli-proxy','--id','private','--domain','cli.test','--path','/private','--action','block')
        self.assertEqual(self.f.p.request('/private',host='cli.test')[0],403)
        self.assertEqual(self.cli('rules','list','--proxy','cli-proxy')[0]['rules'][0]['id'],'private')
        dry=self.cli('rules','remove','--proxy','cli-proxy','--id','private','--dry-run');self.assertTrue(dry['dry_run'])
        self.assertEqual(self.f.p.request('/private',host='cli.test')[0],403)
        exported=Path(self.f.directory)/'config.json';self.cli('config','get','--output',str(exported))
        self.cli('rules','remove','--proxy','cli-proxy','--id','private')
        self.assertEqual(self.f.p.request('/private',host='cli.test')[0],200)
        self.assertIn('409',self.cli('config','apply','--file',str(exported),ok=False)['error'])
        wrong=self.cli('--gateway','http://127.0.0.1:1','status',ok=False);self.assertIn('Not signed in',wrong['error'])
        self.assertTrue(self.cli('auth','status')['authenticated'])
        self.assertTrue(self.cli('auth','logout')['revoked']);self.assertFalse(self.credentials.exists())
        self.assertEqual(self.f.bearer(saved['token'])[0],401)
    def test_read_only_cli_cannot_change_configuration(self):
        login,_=self.login(read_only=True);self.assertEqual(login['scope'],'read')
        self.assertTrue(self.cli('auth','status')['authenticated'])
        self.assertIn('403',self.cli('servers','upsert','--id','server-1','--name','Changed',ok=False)['error'])
        self.assertEqual(self.f.state()['revision'],1)
        self.assertTrue(self.cli('auth','logout')['revoked'])
if __name__=='__main__':unittest.main(defaultTest='CLI',verbosity=2)
