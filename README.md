# Resolve_ip

Capturar IPS,domínios e porta de um site

#!/usr/bin/env python3
# resolve_ip.py - Resolve IPs + hostname reverso + checagem de portas + provedor
# Uso:
#   python resolve_ip.py google.com uol.com.br
#   python resolve_ip.py -f sites.txt
#   python resolve_ip.py -f sites.txt --json saida.json
#   python resolve_ip.py -p 80,443,8443 google.com

import socket
import sys
import json
import argparse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 3

# Portas padrão verificadas quando não se usa -p
PORTAS_PADRAO = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993,
                 1433, 3306, 3389, 5432, 8080, 8443, 8888, 9200, 5555]

def resolver(dominio):
    try:
        infos = socket.getaddrinfo(dominio, None)
        v4 = sorted({r[4][0] for r in infos if r[0] == socket.AF_INET})
        v6 = sorted({r[4][0] for r in infos if r[0] == socket.AF_INET6})
        return v4, v6
    except socket.gaierror:
        return None, None

def hostname_reverso(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "-"

def checar_porta(ip, porta):
    try:
        with socket.create_connection((ip, porta), timeout=TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def info_provedor(ip):
    try:
        req = urllib.request.Request(f"https://ipinfo.io/{ip}/json",
                                     headers={"User-Agent": "resolve-ip/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            d = json.loads(r.read())
        org = d.get("org", "-")
        geo = f"{d.get('city','-')}/{d.get('country','-')}"
        return org, geo
    except Exception:
        return "-", "-"

def processar(dominio, portas):
    resultado = {"dominio": dominio, "ips": []}
    v4, v6 = resolver(dominio)
    if not v4 and not v6:
        print(f"\n=== {dominio} ===\n  [!] Não foi possível resolver")
        return resultado

    print(f"\n=== {dominio} ===")
    for ip in (v4 or []) + (v6 or []):
        ptr = hostname_reverso(ip)
        org, geo = info_provedor(ip)
        abertas = []
        for porta in portas:
            if checar_porta(ip, porta):
                abertas.append(porta)
        print(f"  IP: {ip}")
        print(f"    Hostname reverso : {ptr}")
        print(f"    Provedor         : {org}")
        print(f"    Localização      : {geo}")
        print(f"    Portas abertas   : {', '.join(map(str, abertas)) or 'nenhuma'}")
        resultado["ips"].append({
            "ip": ip, "ptr": ptr, "provedor": org, "geo": geo,
            "portas_abertas": abertas
        })
    return resultado

def main():
    ap = argparse.ArgumentParser(description="Resolve domínios, mostra IP, PTR, provedor e portas abertas")
    ap.add_argument("dominios", nargs="*", help="domínios para resolver")
    ap.add_argument("-f", "--file", help="arquivo com lista de domínios (um por linha)")
    ap.add_argument("-p", "--portas", help="portas separadas por vírgula (padrão: lista comum)")
    ap.add_argument("--json", dest="json_out", help="salvar resultado em arquivo JSON")
    args = ap.parse_args()

    dominios = list(args.dominios)
    if args.file:
        with open(args.file) as f:
            dominios += [l.strip() for l in f if l.strip()]
    if not dominios:
        ap.print_help()
        return

    portas = ([int(p) for p in args.portas.split(",")] if args.portas else PORTAS_PADRAO)

    resultados = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(processar, d, portas) for d in dominios]
        for fut in futures:
            resultados.append(fut.result())

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(resultados, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Resultado salvo em {args.json_out}")

if __name__ == "__main__":
    main()
