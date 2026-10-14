# (name, code, expected set of rule IDs)
CASES = [
 ("SQLi f-string", 'def g(cur,u):\n    cur.execute(f"SELECT * FROM users WHERE name=\'{u}\'")\n', {"SQLI"}),
 ("SQLi format+percent", 'def q(cur,a,b):\n    cur.execute("SELECT * FROM t WHERE a={}".format(a))\n    cur.execute("SELECT * FROM t WHERE b=%s" % b)\n', {"SQLI"}),
 ("SQLi concat", 'def q(cur,a):\n    cur.execute("SELECT * FROM t WHERE a=\'" + a + "\'")\n', {"SQLI"}),
 ("Secret + md5", 'API_KEY = "sk-live-12345678"\nimport hashlib\nh = hashlib.md5(b"x").hexdigest()\n', {"SECRET", "WEAKHASH"}),
 ("sha1 weak hash", 'import hashlib\nh = hashlib.sha1(b"x").hexdigest()\n', {"WEAKHASH"}),
 ("os.system + shell=True", 'import os, subprocess\ndef p(h):\n    os.system("ping " + h)\n    subprocess.run("ls " + h, shell=True)\n', {"CMDI"}),
 ("pickle + eval", 'import pickle\ndef load(b,e):\n    d = pickle.loads(b)\n    return eval(e)\n', {"PICKLE", "EVAL"}),
 ("exec", 'def f(s):\n    exec(s)\n', {"EVAL"}),
 ("TLS off + yaml.load", 'import requests, yaml\nr = requests.get(u, verify=False)\nc = yaml.load(open("c.yml"))\n', {"TLS", "YAML"}),
 ("Flask debug", 'from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n', {"DEBUG"}),
 ("password literal", 'db_password = "hunter2hunter2"\n', {"SECRET"}),
 ("SAFE parameterised", 'def g(cur,u):\n    cur.execute("SELECT * FROM users WHERE name=?", (u,))\n', set()),
 ("SAFE subprocess list", 'import subprocess\nsubprocess.run(["ls","-l"], shell=False)\n', set()),
 ("SAFE sha256 + env secret", 'import os, hashlib\nk = os.environ["API_KEY"]\nh = hashlib.sha256(b"x").hexdigest()\n', set()),
 ("SAFE yaml.safe_load + verify", 'import yaml, requests\nc = yaml.safe_load("a: 1")\nr = requests.get(u, verify=True)\n', set()),
 ("Logic bug only (known miss)", 'def avg(xs):\n    return sum(xs) / len(xs) + 1\n', set()),
]
