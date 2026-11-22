#!/usr/bin/env python3
"""Management authentication, persistence, rollback and live-routing integration tests."""
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from integration import Integration as _Integration, Proxy

class Management(unittest.TestCase):
    @classmethod
    def setUpClass(cls): _Integration.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls): _Integration.tearDownClass.__func__(cls)
    def setUp(self):
        self.directory=tempfile.mkdtemp(dir=self.temp.name)
        self.data=Path(self.directory)/"data"
        os.environ["RUSTGATE_TEST_ADMIN"]="management-test-key-"+"x"*32
        self.key=os.environ["RUSTGATE_TEST_ADMIN"]
        self.p=self.start_proxy()
        self.cookie=None
    def start_proxy(self):
        p=Proxy(self.directory,[o.server_port for o in self.origins],extra=f'admin_token_env = "RUSTGATE_TEST_ADMIN"\nadmin_data_dir = "{self.data}"')
        self.addCleanup(lambda:p.close() if p.process.poll() is None else None)
        return p
    def api(self,path="state",method="GET",value=None,origin="http://a.test",cookie=True):
        c=http.client.HTTPConnection("127.0.0.1",self.p.port,timeout=5)
        headers={"Host":"a.test"}
        if origin is not None:headers["Origin"]=origin
        if cookie and self.cookie:headers["Cookie"]=self.cookie
        body=None
        if value is not None:body=json.dumps(value);headers["Content-Type"]="application/json"
        c.request(method,"/_zntil/admin/"+path,body=body,headers=headers)
        r=c.getresponse();raw=r.read();result=(r.status,json.loads(raw) if raw else {},dict(r.headers));c.close();return result
    def login(self):
        code,_,headers=self.api("login","POST",{"token":self.key},cookie=False)
        self.assertEqual(code,200)
        header=next(v for k,v in headers.items() if k.lower()=="set-cookie")
        self.assertIn("HttpOnly",header);self.assertIn("SameSite=Strict",header)
        self.cookie=header.split(";",1)[0]
    def state(self):
        code,state,_=self.api();self.assertEqual(code,200);return state
    @staticmethod
    def desired(state):return {k:state[k] for k in ["revision","servers","proxies"]}
    def test_management_authentication_and_csrf(self):
        self.assertEqual(self.api(cookie=False)[0],401)
        self.assertEqual(self.api("login","POST",{"token":"wrong"},cookie=False)[0],401)
        self.assertEqual(self.api("login","POST",{"token":self.key},origin="https://evil.test",cookie=False)[0],403)
        self.login();state=self.state()
        self.assertNotIn(self.key,json.dumps(state))
        self.assertNotIn(self.key,(self.data/"control.json").read_text())
        self.assertEqual(self.api("config","PUT",self.desired(state),origin=None)[0],403)
        self.assertEqual(self.api("logout","POST",{},origin="https://evil.test")[0],403)
        self.assertEqual(self.api()[0],200)
        self.assertEqual(self.api("logout","POST",{})[0],204)
        self.assertEqual(self.api()[0],401)
    def test_live_servers_domains_and_conflict(self):
        self.login();state=self.state();desired=self.desired(state)
        desired["proxies"][0]["server_id"]=desired["servers"][1]["id"]
        new=json.loads(json.dumps(desired["proxies"][1]));new.update(id="proxy-new",name="New domain")
        new["route"]["hosts"]=["c.test"];desired["proxies"].append(new)
        code,state,_=self.api("config","PUT",desired);self.assertEqual(code,200);self.assertEqual(state["revision"],2)
        for host in ["a.test","c.test"]:
            code,raw=self.p.request(host=host);self.assertEqual(code,200);self.assertEqual(json.loads(raw)["origin"],self.origins[1].server_port)
        self.assertEqual(self.api("config","PUT",desired)[0],409)
        invalid=self.desired(state);invalid["proxies"][2]["route"]["hosts"]=["a.test"]
        self.assertEqual(self.api("config","PUT",invalid)[0],400)
        self.assertEqual(self.state()["revision"],2)
    def test_rollback_and_restart_persistence(self):
        self.login();desired=self.desired(self.state());desired["proxies"][0]["server_id"]=desired["servers"][1]["id"]
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        code,state,_=self.api("rollback","POST",{"revision":1,"current_revision":2})
        self.assertEqual(code,200);self.assertEqual(state["revision"],3)
        self.assertEqual(json.loads(self.p.request()[1])["origin"],self.origins[0].server_port)
        self.p.close();self.p=self.start_proxy();self.cookie=None;self.login()
        self.assertEqual(self.state()["revision"],3)
        self.assertEqual(json.loads(self.p.request()[1])["origin"],self.origins[0].server_port)
    def test_inflight_request_keeps_its_original_upstream(self):
        self.login();before=[]
        t=threading.Thread(target=lambda:before.append(json.loads(self.p.request("/slow")[1])["origin"]))
        t.start();time.sleep(.2)
        desired=self.desired(self.state());desired["proxies"][0]["server_id"]=desired["servers"][1]["id"]
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        t.join();self.assertEqual(before,[self.origins[0].server_port])
        self.assertEqual(json.loads(self.p.request()[1])["origin"],self.origins[1].server_port)
    def test_failed_persistence_does_not_apply(self):
        self.login();desired=self.desired(self.state());desired["proxies"][0]["server_id"]=desired["servers"][1]["id"]
        moved=self.data.with_name("saved-data");self.data.rename(moved);self.data.write_text("not a directory")
        try:
            self.assertEqual(self.api("config","PUT",desired)[0],500)
            self.assertEqual(self.state()["revision"],1)
            self.assertEqual(json.loads(self.p.request()[1])["origin"],self.origins[0].server_port)
        finally:self.data.unlink();moved.rename(self.data)
    def test_activity_is_sanitized_and_excludes_console_polling(self):
        self.login();before=self.state()["counters"]["requests"]
        self.state();self.assertEqual(self.state()["counters"]["requests"],before)
        self.assertEqual(self.p.request("/.git/config?secret=do-not-retain")[0],403)
        state=self.state();serialized=json.dumps(state)
        self.assertNotIn("do-not-retain",serialized);self.assertNotIn("127.0.0.1",json.dumps(state["events"]))
        self.assertEqual(state["events"][0]["outcome"],"blocked")
        self.assertEqual(state["events"][0]["reason"],"probe_path")
        self.assertEqual(state["traffic"][-1]["blocked"],1)
    def test_public_home_and_console_are_isolated_by_hostname(self):
        p=Proxy(self.directory,[o.server_port for o in self.origins],extra=f'admin_token_env = "RUSTGATE_TEST_ADMIN"\nadmin_data_dir = "{self.data}/isolated"\nadmin_host = "console.test"')
        self.addCleanup(p.close)
        def get(path,host):
            c=http.client.HTTPConnection("127.0.0.1",p.port,timeout=5)
            c.request("GET",path,headers={"Host":host});r=c.getresponse();raw=r.read();code=r.status;c.close();return code,raw
        for path in ["/", "/home.css", "/console/", "/_zntil/console/app.js", "/_rustgate/console/"]:
            code,raw=get(path,"console.test");self.assertEqual(code,200);self.assertTrue(raw)
        self.assertIn(b"Zntil",get("/","console.test")[1])
        self.assertEqual(get("/_zntil/admin/state","console.test")[0],401)
        self.assertEqual(get("/console/","a.test")[0],404)
        self.assertEqual(get("/_zntil/admin/state","a.test")[0],404)
        self.assertEqual(get("/missing","console.test")[0],404)
        self.assertEqual(get("/","a.test")[0],200)
    def bearer(self,token,path="state",method="GET",value=None):
        c=http.client.HTTPConnection("127.0.0.1",self.p.port,timeout=5)
        headers={"Host":"a.test","Origin":"http://a.test","Authorization":"Bearer "+token}
        if value is not None:headers["Content-Type"]="application/json"
        c.request(method,"/_zntil/admin/"+path,body=json.dumps(value) if value is not None else None,headers=headers)
        r=c.getresponse();raw=r.read();out=(r.status,json.loads(raw) if raw else {});c.close();return out
    def device_token(self,write=False):
        code,start,_=self.api("device/start","POST",{"name":"integration agent","write":write},cookie=False)
        self.assertEqual(code,200);self.assertNotIn("device_code",start["verification_uri"])
        self.assertEqual(self.api("device/approve","POST",{"user_code":start["user_code"],"approve":True})[0],200)
        code,result,_=self.api("device/poll","POST",{"device_code":start["device_code"]},cookie=False)
        self.assertEqual(code,200);return start,result
    def test_cli_device_flow_scopes_revocation_and_single_use(self):
        self.login();start,token=self.device_token(False);secret=token["access_token"]
        self.assertEqual(self.bearer(secret)[0],200)
        desired=self.desired(self.state());self.assertEqual(self.bearer(secret,"config","PUT",desired)[0],403)
        self.assertEqual(self.bearer(secret,"validate","POST",desired)[0],200)
        self.assertEqual(self.bearer(secret,"device/approve","POST",{"user_code":start["user_code"],"approve":True})[0],403)
        self.assertEqual(self.bearer(secret,"tokens")[0],403)
        self.assertEqual(self.api("device/poll","POST",{"device_code":start["device_code"]},cookie=False)[0],400)
        self.assertNotIn(secret,(self.data/"credentials.json").read_text())
        self.assertNotIn(secret,json.dumps(self.api("tokens")[1]))
        self.assertEqual(self.api("tokens/revoke","POST",{"token_id":token["token_id"]})[0],200)
        self.assertEqual(self.bearer(secret)[0],401)
    def test_cli_credential_survives_restart_and_can_revoke_itself(self):
        self.login();_,token=self.device_token(True);secret=token["access_token"]
        self.p.close();self.p=self.start_proxy();self.cookie=None
        self.assertEqual(self.bearer(secret)[0],200)
        state=self.bearer(secret)[1];self.assertEqual(self.bearer(secret,"config","PUT",self.desired(state))[0],200)
        self.assertEqual(self.bearer(secret,"tokens/revoke-self","POST",{})[0],200)
        self.assertEqual(self.bearer(secret)[0],401)
    def test_master_key_rotation_durably_revokes_cli_credentials(self):
        self.login();_,token=self.device_token(False);original=self.key
        self.p.close();os.environ["RUSTGATE_TEST_ADMIN"]="rotated-management-key-"+"y"*32;self.key=os.environ["RUSTGATE_TEST_ADMIN"]
        self.p=self.start_proxy();self.assertEqual(self.bearer(token["access_token"])[0],401)
        self.p.close();os.environ["RUSTGATE_TEST_ADMIN"]=original;self.key=original;self.p=self.start_proxy()
        self.assertEqual(self.bearer(token["access_token"])[0],401)
    def test_cli_pending_denial_and_origin_checks(self):
        self.login();code,start,_=self.api("device/start","POST",{"name":"pending"},cookie=False);self.assertEqual(code,200)
        self.assertEqual(self.api("device/poll","POST",{"device_code":start["device_code"]},cookie=False)[0],202)
        self.assertEqual(self.api("device/poll","POST",{"device_code":start["device_code"]},cookie=False)[0],429)
        self.assertEqual(self.api("device/approve","POST",{"user_code":start["user_code"],"approve":False},origin="https://evil.test")[0],403)
        self.assertEqual(self.api("device/approve","POST",{"user_code":start["user_code"],"approve":False})[0],200)
        time.sleep(2.05)
        self.assertEqual(self.api("device/poll","POST",{"device_code":start["device_code"]},cookie=False)[0],403)
    def test_custom_rule_domain_path_method_and_cidr(self):
        self.login();desired=self.desired(self.state());r=desired["proxies"][0]["route"];r["hosts"].append("c.test")
        r["rules"]=[{"id":"private","name":"Private POSTs","domains":["c.test"],"path":"/private","path_match":"prefix","methods":["POST"],"client_cidrs":["127.0.0.0/8"],"action":"block"}]
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        self.assertEqual(self.p.request("/private",host="a.test",method="POST")[0],200)
        self.assertEqual(self.p.request("/private",host="c.test")[0],200)
        self.assertEqual(self.p.request("/private/users",host="c.test",method="POST")[0],403)
        self.assertEqual(self.p.request("/%70rivate",host="c.test",method="POST")[0],403)
        self.assertEqual(self.p.request("/privately",host="c.test",method="POST")[0],200)
        self.assertTrue(any(e["reason"]=="custom_rule_block" for e in self.state()["events"]))
    def test_custom_rate_rule_and_rollback(self):
        self.login();desired=self.desired(self.state());desired["proxies"][0]["route"]["rules"]=[{"id":"limited","name":"Limited","path":"/limited","path_match":"exact","action":"rate_limit","requests_per_second":0.1,"burst":1}]
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        self.assertEqual(self.p.request("/limited")[0],200);self.assertEqual(self.p.request("/limited")[0],429)
        self.assertEqual(self.p.request("/limited/child")[0],200);self.assertEqual(self.p.request("/limited",host="b.test")[0],200)
        self.assertEqual(self.api("rollback","POST",{"revision":1,"current_revision":2})[0],200)
        self.assertEqual(self.p.request("/limited")[0],200)
    def test_custom_rules_observe_mode_and_disable(self):
        self.p.close();self.p=Proxy(self.directory,[o.server_port for o in self.origins],mode="observe",extra=f'admin_token_env="RUSTGATE_TEST_ADMIN"\nadmin_data_dir="{self.data}"');self.addCleanup(self.p.close)
        self.login();desired=self.desired(self.state())
        desired["proxies"][0]["route"]["rules"]=[{"id":"all","name":"Observe all","path":"/","action":"block"},{"id":"slow","name":"Observe rate","path":"/","action":"rate_limit","requests_per_second":0.1,"burst":1}]
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        self.assertEqual(self.p.request('/custom')[0],200);self.assertEqual(self.p.request('/custom')[0],200)
        state=self.state();self.assertEqual(state["counters"]["observed"],2)
        desired=self.desired(state)
        for rule in desired["proxies"][0]["route"]["rules"]:rule["enabled"]=False
        self.assertEqual(self.api("config","PUT",desired)[0],200)
        self.assertEqual(self.p.request('/custom')[0],200);self.assertEqual(self.state()["counters"]["observed"],2)
    def test_invalid_custom_rules_do_not_apply(self):
        self.login();desired=self.desired(self.state());route=desired["proxies"][0]["route"]
        route["rules"]=[{"id":"x","name":"bad domain","domains":["other.test"],"path":"/","action":"block"}]
        self.assertEqual(self.api("config","PUT",desired)[0],400);self.assertEqual(self.state()["revision"],1)
        route["rules"][0]["domains"]=[];route["rules"][0]["action"]="rate_limit"
        self.assertEqual(self.api("validate","POST",desired)[0],400)
    def test_console_assets_and_cache_policy(self):
        for path in ["/_zntil/console/","/_zntil/console/app.js","/_zntil/console/styles.css"]:
            c=http.client.HTTPConnection("127.0.0.1",self.p.port,timeout=5);c.request("GET",path,headers={"Host":"a.test"})
            r=c.getresponse();self.assertEqual(r.status,200);self.assertIn("no-store",r.getheader("cache-control"));self.assertIn("frame-ancestors 'none'",r.getheader("content-security-policy"));self.assertTrue(r.read());c.close()

if __name__=="__main__":unittest.main(defaultTest="Management",verbosity=2)
