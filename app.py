from flask import Flask, render_template, request, redirect, url_for, abort
import subprocess
import csv
import json
import logging
import os
import re
import sys
import time
import hmac
from collections import defaultdict, deque

app = Flask(__name__)
app.config['DEBUG'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024          # limita el tamaño del cuerpo

logging.basicConfig(filename='app.log', level=logging.INFO)

# Caso 3: secretos fuera del código (variables de entorno)
SCAN_TOKEN = os.environ.get('SCAN_TOKEN', '')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# ---------- Caso 6: limitación de intentos (en memoria) ----------
INTENTOS = defaultdict(deque)
VENTANA, MAX_INTENTOS = 60, 10

def limitado(clave):
    ahora = time.time()
    cola = INTENTOS[clave]
    while cola and ahora - cola[0] > VENTANA:
        cola.popleft()
    if len(cola) >= MAX_INTENTOS:
        return True
    cola.append(ahora)
    return False

# ---------- Caso 5: forzar HTTPS ----------
@app.before_request
def forzar_https():
    proto = request.headers.get('X-Forwarded-Proto', request.scheme)
    if proto != 'https' and os.environ.get('ALLOW_HTTP') != '1':
        return redirect(request.url.replace('http://', 'https://', 1), code=301)

# ---------- Caso 4: cabeceras de seguridad (CSP, HSTS, etc.) ----------
@app.after_request
def cabeceras(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp

# ---------- Caso 2: manejo seguro de errores ----------
@app.errorhandler(400)
def err400(e):
    return "Solicitud inválida", 400

@app.errorhandler(500)
def err500(e):
    app.logger.error("Error interno", exc_info=e)       # detalle solo en el log
    return "Ocurrió un error. Intente más tarde.", 500

def neutralizar_csv(valor):
    """Evita CSV/Formula Injection: =, +, -, @ al inicio."""
    valor = valor.strip()
    return "'" + valor if valor[:1] in ('=', '+', '-', '@', '\t', '\r') else valor

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_client', methods=['POST'])
def add_client():
    if limitado(request.remote_addr):
        return "Demasiadas solicitudes", 429
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    if not (1 <= len(name) <= 80) or not EMAIL_RE.match(email) or len(email) > 120:
        return "Datos inválidos", 400
    with open('clients.csv', 'a', newline='', encoding='utf-8') as file:
        csv.writer(file).writerow([neutralizar_csv(name), neutralizar_csv(email)])
    return redirect(url_for('index'))

@app.route('/security_scan')
def security_scan():
    # Control de acceso: solo con token de administrador
    token = request.headers.get('X-Admin-Token', '')
    if not SCAN_TOKEN or not hmac.compare_digest(token, SCAN_TOKEN):
        abort(403)
    if limitado('scan:' + request.remote_addr):
        return "Demasiadas solicitudes", 429

    results = {
        'bandit': {'success': False, 'results': [], 'error': None},
        'pip_audit': {'success': False, 'vulnerabilities': [], 'error': None}
    }
    python_exec = sys.executable
    comandos = {
        'bandit': ([python_exec, '-m', 'bandit', '-r', '.', '-f', 'json', '-c', '.bandit.yml'], 120),
        'pip_audit': ([python_exec, '-m', 'pip_audit', '--format', 'json'], 60),
    }
    for nombre, (cmd, tiempo) in comandos.items():
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=tiempo)  # nosec B603
            data = json.loads(p.stdout) if p.stdout.strip() else None
            if data is None:
                results[nombre]['error'] = "La herramienta no generó salida"
            else:
                results[nombre] = data
                results[nombre]['success'] = True
        except Exception:
            # Mensaje genérico al usuario; detalle solo en el log (Caso 2)
            app.logger.error("Fallo en %s", nombre, exc_info=True)
            results[nombre]['error'] = "No se pudo completar el análisis"
    return render_template('results.html', results=results)

if __name__ == '__main__':
    # Escucha solo en localhost; en producción, detrás de un proxy con TLS
    app.run(host=os.environ.get('APP_HOST', '127.0.0.1'), port=5000, debug=False)
