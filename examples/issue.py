#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""领一张通行证的完整流程，只用 Python 标准库 + cryptography。
这就是给外部 agent 的参考客户端 —— 会一起放进 GitHub 仓库的 examples/。
"""
import json
import os
import sys
import urllib.request

import passport as P
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8402"


def call(path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "wlp-example-client/1.0")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def main():
    # 1. 本地生成密钥。私钥永远不出这台机器。
    keyfile = os.path.expanduser("~/.wlp_example_key.json")
    priv, pub = P.new_agent_key(keyfile)
    pb = P.b64u(pub)
    print("① 公钥 %s…" % pb[:24])
    print("   sub  %s" % P.sub_from_pubkey(pub))

    # 2. 领挑战
    ch = call("/passport/challenge", {"pubkey": pb})
    print("② 挑战 %s…  要签的字: %s…" % (ch["nonce"][:16], ch["sign_this"][:40]))

    # 3. 签给它看
    sig = P.issue_proof(priv, ch["nonce"], pb)
    r = call("/passport/issue", {"pubkey": pb, "nonce": ch["nonce"],
                                 "sig": sig, "handle": "example-client"})
    print("③ 拿到凭证 tier=%s  长度=%d" % (r["tier"], len(r["passport"])))

    # 4. 自己验一遍（不需要问服务器）
    keys_doc = call("/.well-known/walnut-passport-keys.json")
    keys = {k["kid"]: P.b64u_dec(k["x"]) for k in keys_doc["keys"]}
    ok, payload, why = P.verify(r["passport"], keys)
    print("④ 离线自验 ok=%s why=%s" % (ok, why))

    # 5. 带证请求，看身份有没有被认出来
    w = call("/api/passport/verify?token=" + r["passport"])
    print("⑤ 服务端验 %s" % w["ok"])

    # 6. 重放同一个 nonce —— 必须被拒
    try:
        call("/passport/issue", {"pubkey": pb, "nonce": ch["nonce"],
                                 "sig": sig, "handle": "example-client"})
        print("⑥ 重放 没被拦住 ← 这是 bug")
    except urllib.error.HTTPError as e:
        print("⑥ 重放被拒 %s %s" % (e.code, json.loads(e.read().decode())["error"]))

    # 7. 换个私钥冒充同一个 sub —— 签名对不上
    fake = Ed25519PrivateKey.generate()
    try:
        ch2 = call("/passport/challenge", {"pubkey": pb})
        bad = P.b64u(fake.sign(("%s|%s|%s" % (P.ISSUE_CTX, ch2["nonce"], pb)).encode()))
        call("/passport/issue", {"pubkey": pb, "nonce": ch2["nonce"],
                                 "sig": bad, "handle": "impostor"})
        print("⑦ 冒名 没被拦住 ← 这是 bug")
    except urllib.error.HTTPError as e:
        print("⑦ 冒名被拒 %s %s" % (e.code, json.loads(e.read().decode())["error"]))


if __name__ == "__main__":
    main()
