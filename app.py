from flask import Flask, render_template, request, redirect, url_for
import subprocess
import csv
import json
import traceback
import os
import sys

app = Flask(__name__)
app.config['DEBUG'] = False 

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_client', methods=['POST'])
def add_client():
    name = request.form['name']
    email = request.form['email']
    
    if not name or '@' not in email:
        return "Datos inválidos", 400
    
    # Guardar en CSV
    with open('clients.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([name, email])
    
    return redirect(url_for('index'))

@app.route('/security_scan')
def security_scan():
    results = {
        'bandit': {'success': False, 'results': [], 'error': None},
        'pip_audit': {'success': False, 'vulnerabilities': [], 'error': None}
    }
    
    python_exec = sys.executable
    
    try:
        bandit_cmd = [
            python_exec, 
            '-m', 'bandit', 
            '-r', '.', 
            '-f', 'json', 
            '-c', '.bandit.yml'
        ]
        
        bandit = subprocess.run(
            bandit_cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.getcwd() 
        )
        
        # Manejar salida de Bandit
        if bandit.stdout.strip():
            try:
                bandit_data = json.loads(bandit.stdout)
                results['bandit'] = bandit_data
                results['bandit']['success'] = True
            except json.JSONDecodeError:
                results['bandit']['error'] = f"Salida JSON inválida: {bandit.stdout[:100]}"
        else:
            results['bandit']['error'] = "Bandit no generó salida"
            
    except subprocess.TimeoutExpired:
        results['bandit']['error'] = "Bandit excedió el tiempo límite"
    except Exception as e:
        results['bandit']['error'] = f"Error en Bandit: {str(e)}"
        app.logger.error(f"Bandit error: {traceback.format_exc()}")
    
    # 2. Ejecutar pip-audit
    try:
        pip_audit_cmd = [
            python_exec, 
            '-m', 'pip_audit', 
            '--format', 'json'
        ]
        
        pip_audit = subprocess.run(
            pip_audit_cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.getcwd()
        )
        
        # Manejar salida de pip-audit
        if pip_audit.stdout.strip():
            try:
                pip_audit_data = json.loads(pip_audit.stdout)
                results['pip_audit'] = pip_audit_data
                results['pip_audit']['success'] = True
            except json.JSONDecodeError:
                results['pip_audit']['error'] = f"Salida JSON inválida: {pip_audit.stdout[:100]}"
        else:
            results['pip_audit']['error'] = "pip-audit no generó salida"
            
    except Exception as e:
        results['pip_audit']['error'] = f"Error en pip-audit: {str(e)}"
        app.logger.error(f"pip-audit error: {traceback.format_exc()}")
    
    return render_template('results.html', results=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
