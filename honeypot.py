from flask import Flask, request, send_file, abort
import os
import json
import datetime

app = Flask(__name__)

LOG_FILE = 'iot_honeypot.log'

@app.before_request
def log_every_single_request():
    if request.path in ['/static/dahua-logo.png', '/dahua_lens.png']:
        return None

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    print(f"[{request.method}] {request.remote_addr} -> {request.url} | Data: {username}:{password}")

    log_entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
        "attacker_ip": request.remote_addr,
        "method": request.method,
        "requested_url": request.url,
        "username": username,
        "password": password,
        "user_agent": request.headers.get('User-Agent', 'Unknown')
    }

    with open(LOG_FILE, 'a', encoding='utf-8') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')

@app.route('/')
@app.route('/Login.html', methods=['GET'])
def index():
    if os.path.exists('Login.html'):
        return send_file('Login.html')
    return "WebServer Error", 404

@app.route('/dahua_logo.png')
def serve_logo():
    if os.path.exists('dahua_logo.png'):
        return send_file('dahua_logo.png', mimetype='image/png')
    return abort(404)

@app.route('/dahua_lens.png')
def serve_lens():
    if os.path.exists('dahua_lens.png'):
        return send_file('dahua_lens.png', mimetype='image/png')
    return abort(404)

@app.route('/Login.html', methods=['POST'])
def login_post():
    return "Unauthorized", 401

@app.errorhandler(404)
def page_not_found(e):
    return "Not Found", 404

@app.after_request
def add_headers(response):
    response.headers['Server'] = 'Dahua-WebServer/1.0'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
