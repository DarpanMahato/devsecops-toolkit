from flask import Flask, request, abort
import sqlite3
import os

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # Create a sample table with test data
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    cursor.execute("INSERT INTO users (name) VALUES (?)", ("alice",))
    cursor.execute("INSERT INTO users (name) VALUES (?)", ("bob",))
    conn.commit()
    return conn

@app.route('/')
def index():
    return '<h1>Secure Demo App</h1><p>DevSecOps Toolkit sample application.</p>'

@app.route('/search')
def search():
    query = request.args.get('q', '')

    # Input validation
    if not query or len(query) > 100:
        abort(400)

    # Parameterised query — no SQL injection possible
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE name = ?", (query,))
    results = cursor.fetchall()
    conn.close()

    # Return plain text, not user input directly
    count = len(results)
    return f'<p>Found {count} result(s).</p>', 200, {'Content-Type': 'text/html'}

@app.errorhandler(400)
def bad_request(e):
    return '<p>Bad request.</p>', 400

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='127.0.0.1', port=5000, debug=debug_mode)