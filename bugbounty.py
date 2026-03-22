#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════╗
║         BUG BOUNTY RECON TOOLKIT             ║
║   Web security scanner - educational use     ║
╚══════════════════════════════════════════════╝
Uso: python3 bugbounty.py <target>
Ex:  python3 bugbounty.py manifestoapplucas.vercel.app
"""

import sys, socket, ssl, json, re, time, urllib.request, urllib.parse
import http.client, threading, os
from datetime import datetime

# Forcar UTF-8 no stdout (fix Windows cp1252)
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── cores ANSI ────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
X  = "\033[0m"

TARGET = sys.argv[1] if len(sys.argv) > 1 else "manifestoapplucas.vercel.app"
BASE   = f"https://{TARGET}"
FINDINGS = []
START  = datetime.now()

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║          BUG BOUNTY RECON TOOLKIT v1.1               ║
║          target: {W}{TARGET:<35}{C}║
╚══════════════════════════════════════════════════════╝{X}
{DIM}  iniciado em {START.strftime('%Y-%m-%d %H:%M:%S')}{X}
""")

def section(title):
    print(f"\n{B}--- {title} {'-' * (50 - len(title))}{X}")

def found(severity, title, detail):
    icons = {"CRITICAL":"[!!]","HIGH":"[!] ","MEDIUM":"[~] ","LOW":"[-] ","INFO":"[i] "}
    colors= {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":B,"INFO":DIM}
    c = colors.get(severity, W)
    i = icons.get(severity, "[?]")
    print(f"  {c}{i} [{severity}]{X} {W}{title}{X}")
    print(f"      {DIM}{detail}{X}")
    FINDINGS.append({"severity": severity, "title": title, "detail": detail})

def info(msg):
    print(f"  {DIM}> {msg}{X}")

def ok(msg):
    print(f"  {G}[+]{X} {msg}")

def warn(msg):
    print(f"  {Y}[!]{X} {msg}")

def fetch(url, method="GET", headers=None, timeout=8):
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (BugBounty-Recon/1.1)")
        req.add_header("Accept", "*/*")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except:
            body = ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return None, {}, str(e)

# ─────────────────────────────────────────────
# 1. DNS + Subdomínios
# ─────────────────────────────────────────────
def check_dns():
    section("1. DNS & INFRAESTRUTURA")
    try:
        ip = socket.gethostbyname(TARGET)
        ok(f"IP resolvido: {W}{ip}{X}")

        cdns = {
            "vercel":     ["76.76.","76.223.","216.198.","64.29.","64.248."],
            "cloudflare": ["104.16.","104.17.","172.64.","172.65.","172.66.",
                           "172.67.","162.158.","198.41.","103.21.","103.22."],
            "aws":        ["3.","13.","18.","52.","54.","34.","35."],
            "fastly":     ["151.101."],
            "github":     ["185.199."],
            "netlify":    ["104.198.","75.2.","99.83."],
        }
        cdn_detected = None
        for cdn, prefixes in cdns.items():
            if any(ip.startswith(p) for p in prefixes):
                cdn_detected = cdn
                break
        if cdn_detected:
            ok(f"CDN detectado: {C}{cdn_detected.upper()}{X}")
            info("IP real do servidor oculto pelo CDN")
        else:
            found("INFO", "IP direto exposto", f"Servidor em {ip} sem CDN identificado")

        # Subdomínios comuns — verificar DNS + HTTP para evitar wildcard falso positivo
        subs = ["www","api","dev","staging","beta","admin","dashboard",
                "app","auth","login","mail","test","old","backup",
                "docs","status","blog","v1","v2","api2","internal","prod","preprod","qa","uat"]
        info(f"Testando {len(subs)} subdomínios (DNS + HTTP)...")

        # Verificar se o domínio tem wildcard DNS
        # Tentamos um subdomínio aleatório — se resolver, é wildcard
        import random, string
        rand_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
        try:
            wildcard_ip = socket.gethostbyname(f"{rand_sub}.{TARGET}")
            is_wildcard = True
            info(f"Wildcard DNS detectado ({rand_sub}.{TARGET} -> {wildcard_ip}) -- confirmando por HTTP")
        except:
            is_wildcard = False
            wildcard_ip = None

        confirmed_subs = []
        for sub in subs:
            fqdn = f"{sub}.{TARGET}"
            try:
                sub_ip = socket.gethostbyname(fqdn)
            except:
                continue  # não resolve = não existe

            # Se for wildcard, só confirmar se HTTP retorna conteúdo real (não 404/redirect)
            if is_wildcard:
                st, _, body = fetch(f"https://{fqdn}", timeout=5)
                if st is None or st in (404, 410):
                    continue
                # Vercel retorna 404 com body HTML mesmo assim — checar conteúdo
                if st == 404 or (body and ("not found" in body[:300].lower()
                                           or "404" in body[:200])):
                    continue
                # Conteúdo real com status 200/301/302 — subdomínio existe de verdade
                confirmed_subs.append((fqdn, sub_ip, st))
            else:
                confirmed_subs.append((fqdn, sub_ip, None))

        if confirmed_subs:
            for fqdn, sub_ip, st in confirmed_subs:
                label = f"HTTP {st}" if st else f"IP {sub_ip}"
                sev = "MEDIUM" if any(w in fqdn for w in
                      ["admin","api","dev","staging","internal","prod","preprod"]) else "INFO"
                found(sev, f"Subdominio ativo confirmado: {fqdn}",
                      f"{label} -- investigar conteudo e headers de seguranca")
        else:
            ok("Nenhum subdominio confirmado (DNS wildcard sem conteudo real)")

    except Exception as e:
        warn(f"DNS falhou: {e}")

# ─────────────────────────────────────────────
# 2. SSL/TLS (fix Windows)
# ─────────────────────────────────────────────
def check_ssl():
    section("2. SSL / TLS")
    try:
        # Passo 1: conectar sem verificar CA para pegar DER + TLS info
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
        conn.settimeout(8)
        conn.connect((TARGET, 443))
        cert_bin = conn.getpeercert(binary_form=True)  # DER sempre disponivel
        tls_ver  = conn.version()
        cipher   = conn.cipher()
        conn.close()

        if not cert_bin:
            found("HIGH", "Certificado SSL ausente", "Servidor nao apresentou certificado DER")
            return

        ok(f"Certificado DER recebido ({len(cert_bin)} bytes)")

        # Passo 2: tentar parsear campos (CN, expiracao, SANs) via CERT_OPTIONAL
        cert = {}
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_OPTIONAL
            try: ctx2.load_default_certs()
            except: pass
            conn2 = ctx2.wrap_socket(socket.socket(), server_hostname=TARGET)
            conn2.settimeout(8)
            conn2.connect((TARGET, 443))
            cert = conn2.getpeercert() or {}
            conn2.close()
        except Exception:
            pass  # campos parsed indisponiveis, mas temos DER

        # Expiracao
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_dt - datetime.now()).days
            if days_left < 7:
                found("CRITICAL", "Certificado SSL quase expirado",
                      f"Expira em {days_left} dias - URGENTE ({expire_str})")
            elif days_left < 30:
                found("HIGH", "Certificado SSL proximo do vencimento",
                      f"Expira em {days_left} dias ({expire_str})")
            else:
                ok(f"Certificado valido por {G}{days_left}{X} dias")

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "?")
        ok(f"CN: {W}{cn}{X}")

        # SANs
        sans = cert.get("subjectAltName", [])
        if sans:
            san_list = [v for _, v in sans[:6]]
            info(f"SANs: {', '.join(san_list)}")

        # Versao TLS
        if tls_ver in ("TLSv1", "TLSv1.1"):
            found("MEDIUM", f"Versao TLS antiga: {tls_ver}",
                  "TLS 1.0/1.1 sao obsoletos (POODLE, BEAST). Usar TLS 1.2+")
        else:
            ok(f"Versao TLS: {W}{tls_ver}{X}")

        # Cipher
        if cipher:
            cipher_name = cipher[0]
            if any(w in cipher_name for w in ["RC4","DES","NULL","EXPORT","anon","3DES"]):
                found("HIGH", f"Cipher fraco: {cipher_name}",
                      "Algoritmo obsoleto ou inseguro")
            else:
                ok(f"Cipher: {DIM}{cipher_name}{X}")

        # Self-signed -- ignorar se issuer e uma CA conhecida (Let's Encrypt, DigiCert etc)
        if cert.get("issuer"):
            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_txt = (issuer.get("organizationName","") + issuer.get("commonName","")).lower()
            known_cas = ["let's encrypt","letsencrypt","digicert","comodo","sectigo",
                         "globalsign","amazon","google trust","cloudflare","entrust",
                         "zerossl","buypass","godaddy","verisign","geotrust"]
            is_known_ca = any(ca in issuer_txt for ca in known_cas)
            if not is_known_ca and subject.get("commonName") == issuer.get("commonName","x"):
                found("MEDIUM", "Certificado self-signed",
                      "Nao emitido por CA reconhecida -- browser mostrara aviso")

    except ConnectionRefusedError:
        found("MEDIUM", "HTTPS indisponivel na porta 443",
              "Servidor nao aceita conexoes TLS")
    except Exception as e:
        warn(f"SSL check falhou: {e}")

# ─────────────────────────────────────────────
# 3. Security Headers
# ─────────────────────────────────────────────
def check_headers():
    section("3. SECURITY HEADERS")
    # Tentar varios endpoints para pegar os headers reais (alguns sites bloqueiam /)
    status, headers, body = fetch(BASE)
    if status == 403 or status is None:
        for probe in [BASE + "/index.html", BASE + "/favicon.ico",
                      BASE + "/robots.txt", BASE + "/"]:
            s2, h2, b2 = fetch(probe, timeout=5)
            if s2 and s2 != 403:
                status, headers, body = s2, h2, b2
                info(f"Headers obtidos via {probe.replace(BASE,'')}")
                break
    if status is None:
        warn(f"Nao conseguiu conectar ao alvo")
        return

    if status == 403:
        info(f"HTTP {status} -- site retorna 403 (protegido/privado) -- headers analisados sao os do bloqueio")
    else:
        info(f"HTTP {status} -- {len(body)} bytes")

    security_headers = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "msg": "HSTS ausente -- HTTPS nao forcado. Vulneravel a downgrade attacks."
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "msg": "CSP ausente -- sem restricao de fontes de scripts. Risco de XSS."
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "msg": "X-Frame-Options ausente -- pagina carregavel em iframe. Risco de Clickjacking."
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "msg": "X-Content-Type-Options ausente -- browser pode fazer MIME sniffing."
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "msg": "Referrer-Policy ausente -- URL completa pode vazar para sites externos."
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "msg": "Permissions-Policy ausente -- APIs sensiveis (camera, mic) nao restritas."
        },
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, meta in security_headers.items():
        val = headers_lower.get(header.lower())
        if val:
            ok(f"{header}: {DIM}{val[:70]}{X}")
            if header == "Content-Security-Policy":
                if "unsafe-inline" in val:
                    found("MEDIUM", "CSP com 'unsafe-inline'",
                          "Permite scripts inline -- mitiga mas nao elimina XSS")
                if "unsafe-eval" in val:
                    found("MEDIUM", "CSP com 'unsafe-eval'",
                          "Permite eval() -- vetor comum de XSS avancado")
                if "*" in val and "default-src" in val:
                    found("MEDIUM", "CSP com wildcard (*) no default-src",
                          "CSP muito permissiva -- nao bloqueia fontes externas")
            if header == "Strict-Transport-Security":
                if "max-age=0" in val:
                    found("MEDIUM", "HSTS com max-age=0", "HSTS efetivamente desabilitado")
                elif "max-age=" in val:
                    age = re.search(r"max-age=(\d+)", val)
                    if age and int(age.group(1)) < 86400:
                        found("LOW", "HSTS com max-age muito curto",
                              f"max-age={age.group(1)}s -- recomendado >= 31536000 (1 ano)")
        else:
            extra = " -- site retorna 403 mas headers de seguranca devem estar presentes mesmo assim" if status == 403 else ""
            found(meta["severity"], f"Header ausente: {header}", meta["msg"] + extra)

    # Information disclosure
    print()
    info("Verificando information disclosure nos headers...")
    leak_headers = {
        "Server":            "Versao/tipo do servidor exposta",
        "X-Powered-By":      "Tecnologia backend exposta",
        "X-AspNet-Version":  "Versao ASP.NET exposta",
        "X-Generator":       "Tecnologia geradora exposta",
        "Via":               "Proxy/CDN interno exposto",
        "X-Runtime":         "Tempo de execucao exposto (Ruby/Rails)",
        "X-Debug-Token":     "Token de debug exposto (Symfony)",
    }
    for h, desc in leak_headers.items():
        val = headers_lower.get(h.lower())
        if val and len(val) > 1:
            found("LOW", f"Info disclosure: {h}", f"{desc} -- valor: '{val[:60]}'")

    # CORS
    cors = headers_lower.get("access-control-allow-origin")
    if cors == "*":
        found("MEDIUM", "CORS aberto: Access-Control-Allow-Origin: *",
              "Qualquer origem pode fazer requests. Critico se combinado com credenciais.")
    elif cors:
        ok(f"CORS: {cors}")

    # Redirect HTTP->HTTPS
    status_http, _, _ = fetch(f"http://{TARGET}", timeout=5)
    if status_http == 200:
        found("MEDIUM", "HTTP sem redirect para HTTPS",
              f"http://{TARGET} retorna 200 -- HTTPS nao forcado na camada de aplicacao")
    elif status_http in (301, 302, 307, 308):
        ok(f"HTTP redireciona para HTTPS (HTTP {status_http})")

# ─────────────────────────────────────────────
# 4. Endpoints sensiveis
# ─────────────────────────────────────────────
def check_paths():
    section("4. ENDPOINTS & CAMINHOS SENSIVEIS")

    paths = [
        # Admin
        ("/admin",             "HIGH",   "Painel admin exposto"),
        ("/admin/",            "HIGH",   "Painel admin exposto"),
        ("/dashboard",         "MEDIUM", "Dashboard exposto"),
        ("/wp-admin",          "LOW",    "WordPress admin"),
        ("/wp-login.php",      "LOW",    "WordPress login"),
        ("/administrator",     "LOW",    "Joomla admin"),
        ("/panel",             "MEDIUM", "Painel de controle"),
        ("/cpanel",            "MEDIUM", "cPanel exposto"),
        # APIs
        ("/api",               "MEDIUM", "API base"),
        ("/api/v1",            "MEDIUM", "API v1"),
        ("/api/v2",            "MEDIUM", "API v2"),
        ("/api/v1/users",      "HIGH",   "Lista de usuarios via API"),
        ("/api/v1/user",       "HIGH",   "Dados de usuario via API"),
        ("/api/users",         "HIGH",   "Endpoint de usuarios"),
        ("/api/auth",          "HIGH",   "Endpoint de autenticacao"),
        ("/api/admin",         "HIGH",   "API admin"),
        ("/api/debug",         "HIGH",   "API debug"),
        ("/api/config",        "HIGH",   "Config via API"),
        ("/graphql",           "HIGH",   "GraphQL endpoint"),
        ("/graphiql",          "HIGH",   "GraphiQL interface"),
        ("/v1/graphql",        "HIGH",   "GraphQL alternativo"),
        # Configs / segredos
        ("/.env",              "CRITICAL","Arquivo .env"),
        ("/.env.local",        "CRITICAL","Arquivo .env.local"),
        ("/.env.production",   "CRITICAL","Arquivo .env.production"),
        ("/.env.development",  "CRITICAL","Arquivo .env.development"),
        ("/.env.staging",      "CRITICAL","Arquivo .env.staging"),
        ("/.git/config",       "HIGH",   "Repositorio Git exposto"),
        ("/.git/HEAD",         "HIGH",   "Git HEAD exposto"),
        ("/.git/COMMIT_EDITMSG","HIGH",  "Git commit message"),
        ("/config.json",       "HIGH",   "Config JSON"),
        ("/config.php",        "HIGH",   "Config PHP"),
        ("/configuration.php", "HIGH",   "Configuration PHP"),
        ("/settings.json",     "HIGH",   "Settings JSON"),
        ("/database.yml",      "HIGH",   "Config de banco"),
        ("/secrets.json",      "CRITICAL","Secrets JSON"),
        ("/credentials.json",  "CRITICAL","Credentials JSON"),
        # Backups
        ("/backup.zip",        "HIGH",   "Backup ZIP"),
        ("/backup.tar.gz",     "HIGH",   "Backup tar.gz"),
        ("/backup.sql",        "CRITICAL","Dump SQL"),
        ("/db.sql",            "CRITICAL","Dump SQL"),
        ("/dump.sql",          "CRITICAL","Dump SQL"),
        (f"/{TARGET}.zip",     "HIGH",   "Backup do site"),
        # Debug / docs
        ("/swagger",           "MEDIUM", "Swagger UI"),
        ("/swagger.json",      "MEDIUM", "Swagger JSON"),
        ("/swagger.yaml",      "MEDIUM", "Swagger YAML"),
        ("/openapi.json",      "MEDIUM", "OpenAPI spec"),
        ("/api-docs",          "MEDIUM", "API docs"),
        ("/docs",              "INFO",   "Documentacao"),
        ("/debug",             "MEDIUM", "Debug endpoint"),
        ("/console",           "HIGH",   "Console (Rails/Symfony)"),
        ("/test",              "LOW",    "Endpoint de teste"),
        ("/health",            "INFO",   "Health check"),
        ("/healthz",           "INFO",   "Health check k8s"),
        ("/status",            "INFO",   "Status endpoint"),
        ("/metrics",           "MEDIUM", "Metricas (Prometheus)"),
        ("/actuator",          "HIGH",   "Spring Boot Actuator"),
        ("/actuator/env",      "CRITICAL","Spring Boot env vars"),
        ("/actuator/health",   "MEDIUM", "Spring Boot health"),
        # Outros
        ("/robots.txt",        "INFO",   "robots.txt"),
        ("/sitemap.xml",       "INFO",   "Sitemap XML"),
        ("/.well-known/security.txt", "INFO", "security.txt"),
        ("/phpinfo.php",       "HIGH",   "phpinfo()"),
        ("/info.php",          "HIGH",   "info.php"),
        ("/server-status",     "MEDIUM", "Apache server-status"),
        ("/server-info",       "MEDIUM", "Apache server-info"),
        ("/nginx_status",      "MEDIUM", "Nginx status"),
        ("/.DS_Store",         "LOW",    ".DS_Store (mac)"),
        ("/Thumbs.db",         "LOW",    "Thumbs.db (windows)"),
        ("/crossdomain.xml",   "LOW",    "crossdomain.xml (Flash)"),
        ("/clientaccesspolicy.xml","LOW","Silverlight policy"),
    ]

    info(f"Testando {len(paths)} caminhos...\n")
    seen = set()

    # Medir o "403 padrao" do servidor para evitar falsos positivos
    # Se /nao-existe-xyzxyz retorna 403, entao 403 e o default do servidor (nao significa que o path existe)
    _, _, default403_body = fetch(BASE + "/nao-existe-xyzxyz-bugbounty", timeout=5)
    default403_len = len(default403_body) if default403_body else 0

    for path, severity, desc in paths:
        url = BASE + path
        status, hdrs, body = fetch(url, timeout=5)

        if status in (200, 201, 202):
            clen = len(body)
            # Filtrar false positives: pagina de erro disfarcada de 200
            is_real = clen > 100
            body_low = body[:500].lower()
            fp_strings = ["404","not found","page not found","does not exist",
                          "couldn't find","no such","error 404"]
            if any(s in body_low for s in fp_strings):
                is_real = False

            if is_real:
                key = f"{status}:{path}"
                if key not in seen:
                    seen.add(key)
                    found(severity, f"[{status}] {path} -- {desc}",
                          f"URL: {url} | {clen} bytes")

                    # Checar .env com credenciais
                    if ".env" in path:
                        cred_patterns = ["DB_","SECRET","KEY=","PASSWORD","TOKEN=",
                                         "API_","DATABASE_URL","REDIS_","AWS_"]
                        if any(p in body for p in cred_patterns):
                            found("CRITICAL", f"CREDENCIAIS em {path}",
                                  "Variaveis de ambiente com dados sensiveis detectadas!")

                    # Checar .git com conteudo
                    if ".git" in path and len(body) > 10:
                        found("HIGH", f"Git exposto: {path}",
                              "Repositorio Git acessivel -- codigo fonte pode ser extraido")

        elif status == 403:
            body_len = len(body) if body else 0
            # So reportar 403 se o body for significativamente diferente do 403 padrao
            # (body diferente indica que o servidor trata esse caminho de forma especial)
            len_diff = abs(body_len - default403_len)
            is_distinct = len_diff > 200  # mais de 200 bytes de diferenca = resposta especial
            if path in ("/.env","/.git/config","/admin","/actuator/env",
                        "/api/users","/graphql","/actuator") and is_distinct:
                found("LOW", f"[403] {path} -- resposta distinta do 403 padrao",
                      f"Body tem {len_diff} bytes a mais que o 403 padrao -- pode indicar "
                      f"que o caminho existe e esta bloqueado. Tentar bypass: "
                      f"X-Original-URL: {path} | X-Rewrite-URL: {path}")
        elif status and status not in (404, 410, 400):
            info(f"[{status}] {path}")

    # Analisar robots.txt
    _, _, robots = fetch(BASE + "/robots.txt")
    if robots and "Disallow:" in robots:
        disallows = re.findall(r"Disallow:\s*(.+)", robots)
        if disallows:
            found("INFO", "robots.txt revela caminhos bloqueados",
                  f"Disallow: {', '.join(d.strip() for d in disallows[:8])}")
            sensitive_words = ["admin","api","config","backup","user","auth",
                               "secret","key","internal","private","token"]
            for d in disallows:
                d = d.strip()
                if any(w in d.lower() for w in sensitive_words):
                    found("MEDIUM", f"Caminho sensivel em robots.txt: {d}",
                          "robots.txt sugere conteudo restrito neste caminho")

# ─────────────────────────────────────────────
# 5. Cookies
# ─────────────────────────────────────────────
def check_cookies():
    section("5. COOKIES & SESSOES")
    endpoints = [BASE, BASE + "/login", BASE + "/api/auth",
                 BASE + "/api/v1/auth", BASE + "/signin"]
    all_cookies = []

    for ep in endpoints:
        _, hdrs, _ = fetch(ep, timeout=5)
        raw = hdrs.get("Set-Cookie") or hdrs.get("set-cookie", "")
        if raw:
            all_cookies.append((ep, raw))

    if not all_cookies:
        info("Nenhum Set-Cookie detectado nos endpoints testados")
        return

    for ep, cookie_str in all_cookies:
        ck_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()
        info(f"Cookie em {ep.replace(BASE,'')}: {W}{name}{X}")

        flags = {
            "httponly": ("LOW",    "Cookie sem HttpOnly",
                         "Acessivel via JS -- risco de roubo por XSS"),
            "secure":   ("MEDIUM", "Cookie sem Secure flag",
                         "Pode ser transmitido em HTTP nao criptografado"),
            "samesite": ("LOW",    "Cookie sem SameSite",
                         "Enviado em requests cross-site -- risco de CSRF"),
        }
        for flag, (sev, title, detail) in flags.items():
            if flag not in ck_lower:
                found(sev, title, detail)
            else:
                ok(f"Flag {flag} presente")

        # Token fraco
        val_m = re.search(r"=([^;,\s]+)", cookie_str)
        if val_m:
            val = val_m.group(1)
            if len(val) < 16:
                found("HIGH", f"Session token curto ({len(val)} chars)",
                      f"Entropia insuficiente -- suscetivel a brute force/predicao")
            # Token numerico sequencial?
            if val.isdigit() and len(val) < 10:
                found("HIGH", "Session token numerico/sequencial",
                      f"Valor: {val} -- provavelmente previsivel (IDOR potencial)")

# ─────────────────────────────────────────────
# 6. Information Disclosure
# ─────────────────────────────────────────────
def check_leaks():
    section("6. INFORMATION DISCLOSURE")
    _, _, body = fetch(BASE)
    if not body:
        warn("Body vazio")
        return

    patterns = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
         "HIGH",     "API Key no HTML"),
        (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
         "HIGH",     "Secret key no HTML"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^\s\'"&]{6,})',
         "CRITICAL", "Senha no HTML"),
        (r'(?i)(token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})',
         "HIGH",     "Token no HTML"),
        (r'(?i)(mongodb|postgres|mysql|redis|mssql):\/\/[^\s\'"<>]+',
         "CRITICAL", "Connection string de banco"),
        (r'(?i)(aws_access_key_id)[^\s]*\s*[=:]\s*([A-Z0-9]{16,})',
         "CRITICAL", "Credencial AWS"),
        (r'ghp_[A-Za-z0-9]{36}',
         "CRITICAL", "GitHub PAT exposto"),
        (r'ghs_[A-Za-z0-9]{36}',
         "CRITICAL", "GitHub Actions token"),
        (r'sk-[A-Za-z0-9]{32,}',
         "CRITICAL", "OpenAI API Key"),
        (r'AIza[0-9A-Za-z\-_]{35}',
         "HIGH",     "Google API Key"),
        (r'(?i)BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY',
         "CRITICAL", "Chave privada exposta"),
        (r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b',
         "MEDIUM",   "CPF no HTML"),
        (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
         "MEDIUM",   "Numero de cartao no HTML"),
        (r'(?i)<!--.*?(todo|fixme|hack|bug|vuln|password|secret|key).*?-->',
         "LOW",      "Comentario HTML sensivel"),
        (r'(?i)console\.(log|warn|error)\(["\'][^)]{15,}',
         "LOW",      "console.log com dados"),
        (r'(?i)(localhost|127\.0\.0\.1):\d{4}',
         "LOW",      "Referencia a localhost"),
        (r'\b192\.168\.\d+\.\d+\b',
         "LOW",      "IP rede privada 192.168.x"),
        (r'\b10\.\d+\.\d+\.\d+\b',
         "LOW",      "IP rede privada 10.x"),
        (r'\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b',
         "LOW",      "IP rede privada 172.x"),
        (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',
         "INFO",     "E-mail no HTML"),
    ]

    info(f"Analisando {len(body)} bytes de HTML por dados sensiveis...")
    seen = set()
    found_count = 0

    for pattern, severity, title in patterns:
        matches = re.findall(pattern, body[:200000])
        for match in matches[:3]:
            val = match if isinstance(match, str) else (match[-1] if match else "")
            key = f"{title}:{val[:20]}"
            if key not in seen:
                seen.add(key)
                found(severity, title,
                      f"Valor: {val[:50]}{'...' if len(val)>50 else ''}")
                found_count += 1

    # Varrer arquivos JS
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
    js_files = list(set(js_files))
    info(f"Encontrados {len(js_files)} arquivos JS -- analisando os primeiros 4...")
    for js in js_files[:4]:
        js_url = js if js.startswith("http") else BASE + ("/" + js).replace("//", "/")
        _, _, js_body = fetch(js_url, timeout=6)
        if not js_body or len(js_body) < 50:
            continue
        for pattern, severity, title in patterns[:12]:
            matches = re.findall(pattern, js_body[:100000])
            for match in matches[:2]:
                val = match if isinstance(match, str) else (match[-1] if match else "")
                key = f"JS:{title}:{val[:20]}"
                if key not in seen:
                    seen.add(key)
                    js_name = js_url.split("/")[-1][:40]
                    found(severity, f"[JS] {title}",
                          f"Arquivo: {js_name} | Valor: {val[:50]}")
                    found_count += 1

    if found_count == 0:
        ok("Nenhum dado sensivel detectado no HTML/JS")

# ─────────────────────────────────────────────
# 7. XSS Reflection
# ─────────────────────────────────────────────
def check_xss():
    section("7. XSS REFLECTION TEST")
    info("Testando reflexao de parametros na URL...")

    payloads = [
        ("<xsstest>",            "xsstest"),
        ('"><img src=x>',        'src=x'),
        ("';alert(xss);//",      "alert(xss)"),
        ("<ScRiPt>xss</ScRiPt>", "xss</ScRiPt>"),
    ]

    _, _, homepage = fetch(BASE)
    param_urls = []
    if homepage:
        links = re.findall(r'href=["\']([^"\']*\?[^"\']{3,})["\']', homepage)
        param_urls = [u if u.startswith("http") else BASE + u for u in links[:5]]

    if not param_urls:
        param_urls = [
            BASE + "/?q=test",
            BASE + "/?search=test",
            BASE + "/?id=1",
            BASE + "/?page=1",
            BASE + "/?lang=pt",
        ]

    tested = set()
    for url in param_urls[:4]:
        if "?" not in url:
            continue
        base_url = url.split("?")[0]
        qs = url.split("?")[1]
        params = urllib.parse.parse_qs(qs)

        for param in list(params.keys())[:2]:
            for payload, marker in payloads[:3]:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                if test_url in tested:
                    continue
                tested.add(test_url)

                status, _, body = fetch(test_url, timeout=5)
                if status is None:
                    info(f"XSS: sem conexao para ?{param}")
                    break
                if status == 200 and body and marker in body:
                    found("HIGH", f"XSS refletido em ?{param}",
                          f"Payload '{payload}' refletido sem encoding\n"
                          f"      URL: {test_url[:100]}")
                    break
                else:
                    info(f"XSS: ?{param} nao refletido (HTTP {status})")

# ─────────────────────────────────────────────
# 8. IDOR / BOLA basico
# ─────────────────────────────────────────────
def check_idor():
    section("8. IDOR / BOLA (acesso a recursos de outros usuarios)")
    info("Testando endpoints com IDs numericos...")

    api_patterns = [
        "/api/v1/users/",
        "/api/v1/user/",
        "/api/users/",
        "/api/user/",
        "/api/v2/users/",
        "/users/",
        "/user/",
        "/profile/",
        "/account/",
    ]

    for pattern in api_patterns:
        for uid in ["1", "2", "3", "100"]:
            url = BASE + pattern + uid
            status, hdrs, body = fetch(url, timeout=5)
            if status == 200 and len(body) > 100:
                body_low = body[:300].lower()
                data_indicators = ["email","name","user","id","username",
                                   "phone","address","role","created"]
                if any(d in body_low for d in data_indicators):
                    found("HIGH", f"Possivel IDOR: {pattern}{uid}",
                          f"HTTP 200 com dados de usuario sem autenticacao\n"
                          f"      URL: {url} | {len(body)} bytes\n"
                          f"      Preview: {body[:100]}...")
                    break
            elif status == 401 or status == 403:
                ok(f"Autenticacao exigida em {pattern}{uid} ({status})")
                break

# ─────────────────────────────────────────────
# 9. Relatorio final
# ─────────────────────────────────────────────
def report():
    elapsed = (datetime.now() - START).total_seconds()
    section("RELATORIO FINAL")

    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    counts = {s: 0 for s in order}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    cols = {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":B,"INFO":DIM}

    print(f"\n  {W}Alvo:{X}    {C}{TARGET}{X}")
    print(f"  {W}Tempo:{X}   {elapsed:.1f}s")
    print(f"  {W}Findings:{X} {len(FINDINGS)} total\n")

    for sev in order:
        n = counts[sev]
        bar = "#" * min(n, 30)
        c = cols[sev]
        print(f"  {c}{sev:<10}{X} {W}{n:>3}{X}  {c}{bar}{X}")

    print()
    if counts["CRITICAL"] > 0:
        print(f"  {R}[!!] CRITICOS encontrados -- reportar IMEDIATAMENTE{X}")
    elif counts["HIGH"] > 0:
        print(f"  {R}[!]  Findings HIGH encontrados -- prioridade imediata{X}")
    elif counts["MEDIUM"] > 0:
        print(f"  {Y}[~]  Findings MEDIUM -- resolver na proxima sprint{X}")
    else:
        print(f"  {G}[+]  Apenas findings baixos/informativos{X}")

    # Listar por severidade decrescente
    print(f"\n  {W}Top findings:{X}")
    for sev in ["CRITICAL","HIGH","MEDIUM"]:
        for f in FINDINGS:
            if f["severity"] == sev:
                print(f"  {cols[sev]}  [{sev}]{X} {f['title']}")

    # Salvar JSON com encoding UTF-8 explícito (fix Windows cp1252)
    out = {
        "target": TARGET,
        "scanned_at": START.isoformat(),
        "duration_seconds": round(elapsed, 2),
        "summary": counts,
        "findings": FINDINGS
    }
    report_file = f"report_{TARGET.replace('.','_').replace(':','_')}.json"
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=True)
        print(f"\n  {G}Relatorio JSON salvo:{X} {report_file}\n")
    except Exception as e:
        warn(f"Erro ao salvar JSON: {e}")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    banner()
    try:
        check_dns()
        check_ssl()
        check_headers()
        check_paths()
        check_cookies()
        check_leaks()
        check_xss()
        check_idor()
    except KeyboardInterrupt:
        print(f"\n{Y}Scan interrompido pelo usuario{X}")
    finally:
        report()