import sqlite3
import html
import re
from flask import Flask, request, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

DB_NAME = "authx.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "cheie_foarte_secreta_si_lunga"

# FIX 10: Insecure Session Cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
# app.config["SESSION_COOKIE_SECURE"]= True - needed to run on localhost
app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'

# Setup pentru token-ul de resetare parola (folosit la FIX 5)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

def log_action(user_id, action, resource=None, resource_id=None):
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""
        INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, action, resource, resource_id, request.remote_addr))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'user_id' in session:
        safe_email = html.escape(session.get('email', ''))
        html_code = f"<h2>Salut, {safe_email}! (AuthX Portal Securizat)</h2>"
        html_code += "<ul>"
        html_code += "<li><a href='/tickets'>Vezi Tichetele Mele</a></li>"
        html_code += "<li><a href='/tickets/new'>Creeaza Ticket</a></li>"
        html_code += "<li><a href='/logout'>Deconectare</a></li>"
        html_code += "</ul>"
        return html_code
    
    html_code = "<h2>Bine ai venit la AuthX v2</h2>"
    html_code += "<a href='/login'>Autentificare (Login)</a> | <a href='/register'>Creare cont (Register)</a>"
    return html_code

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        role = request.form.get("role", "USER")

        # FIX 1: Weak Password Policy
        # Validam complexitatea: minim 8 caractere, minim o cifra
        if len(password) < 8 or not re.search(r"\d", password):
            return "Eroare: Parola trebuie sa aiba minim 8 caractere si cel putin o cifra. <a href='/register'>Inapoi</a>"
        
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            # FIX 2: MD5 Password Storage
            # Folosim werkzeug pentru a genera un hash puternic cu salt
            strong_hash = generate_password_hash(password)

            cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", 
                      (email, strong_hash, role))
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            log_action(user_id=user_id, action="REGISTER", resource='auth')
            return "Cont creat cu succes! <a href='/login'>Mergi la Login</a>"
        except sqlite3.IntegrityError:
            return "Eroare: Eroare la inregistrare. <a href='/register'>Inapoi</a>"
        
    html_code = "<h3>Inregistrare</h3>"
    html_code += "<form method='POST'>"
    html_code += "Email: <input type='text' name='email'><br>"
    html_code += "Parola: <input type='password' name='password'><br>"
    html_code += "Rol:<select name='role'><option value='USER'>USER</option><option value='MANAGER'>MANAGER</option></select>"
    html_code += "<input type='submit' value='Register'>"
    html_code += "</form>"
    return html_code

@app.route('/login', methods=['GET','POST'])
def login():

    if request.method == 'POST':

        email = request.form.get('email', '')
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        # FIX 3: User Enumeration
        # Oferim exact acelasi mesaj de eroare indiferent daca mailul exista sau parola e gresita
        generic_error = "Eroare: Email sau parola incorecta! <a href='/login'>Inapoi</a>"

        if user is None:
            return generic_error
        
        user_id, stored_hash = user

        # FIX 2: Password Hashing
        if check_password_hash(stored_hash, password):
            session['user_id'] = user_id
            session['email'] = email
            log_action(user_id, 'LOGIN_SUCCESS', 'auth')
            return redirect('/')
        else:
            log_action(user_id, 'LOGIN_FAILED', 'auth')
            return generic_error
        
    html_code = "<h3>Autentificare</h3>"
    html_code += "<form method='POST'>"
    html_code += "Email: <input type='text' name='email'><br>"
    html_code += "Parola: <input type='password' name='password'><br>"
    html_code += "<input type='submit' value='Login'>"
    html_code += "</form><br>"
    html_code += "<a href='/forgot-password'>Am uitat parola</a>"
    return html_code

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth')
    session.clear()
    return redirect('/')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # FIX 5: Predictable Reset Token
        # Generam un token criptografic cu semnatura de timp, in loc de base64
        secure_token = serializer.dumps(email, salt='password-reset-salt')
        
        html_code = f"Daca emailul exista, s-a trimis link-ul: <br>"
        html_code += f"<a href='/reset-password?token={secure_token}'>Link Resetare Parola (Expira intr-o ora)</a>"
        return html_code

    html_code = "<h3>Resetare Parola</h3>"
    html_code += "<form method='POST'>"
    html_code += "Introdu email-ul contului: <input type='text' name='email'><br>"
    html_code += "<input type='submit' value='Trimite Link'>"
    html_code += "</form>"
    return html_code

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return "Eroare: Lipseste token-ul."
        
    try:
        # FIX 5: Verificam semnatura si impunem expirare (max 3600 secunde = 1 ora)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return "Eroare: Token-ul a expirat."
    except BadTimeSignature:
        return "Eroare: Token invalid."

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        if len(new_password) < 8:
            return "Parola prea scurta. Minim 8 caractere."

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (generate_password_hash(new_password), email))
        conn.commit()
        conn.close()
        
        return "Parola a fost schimbata! <a href='/login'>Login</a>"

    html_code = f"<h3>Resetare parola pentru: {html.escape(email)}</h3>"
    html_code += "<form method='POST'>"
    html_code += "Parola noua: <input type='password' name='new_password'><br>"
    html_code += "<input type='submit' value='Schimba'>"
    html_code += "</form>"
    return html_code

@app.route('/tickets', methods=['GET'])
def list_tickets():
    if 'user_id' not in session:
        return redirect('/login')
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, severity, status FROM tickets WHERE owner_id = ?", (session['user_id'],))
    tickets = cursor.fetchall()
    conn.close()
    
    safe_email = html.escape(session.get('email', ''))
    html_code = f"<h3>Tichetele Tale (User: {safe_email})</h3>"
    html_code += "<form action='/tickets/search' method='GET'>"
    html_code += "Cauta ticket: <input type='text' name='q'> <input type='submit' value='Cauta'>"
    html_code += "</form><br>"

    html_code += "<table border='1'><tr><th>ID</th><th>Titlu</th><th>Status</th><th>Actiuni</th></tr>"
    for t in tickets:
        # FIX 9: Stored XSS pe titlu/status
        safe_title = html.escape(str(t[1]))
        safe_status = html.escape(str(t[3]))
        html_code += f"<tr><td>{t[0]}</td><td>{safe_title}</td><td>{safe_status}</td>"
        html_code += f"<td><a href='/tickets/{t[0]}'>Vezi</a></td></tr>"
    html_code += "</table><br><a href='/'>Inapoi la meniu</a>"
    
    return html_code

@app.route('/tickets/new', methods=['GET', 'POST'])
def create_ticket():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        severity = request.form.get('severity')
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)",
                  (title, description, severity, session['user_id']))
        ticket_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_action(session['user_id'], 'CREATE_TICKET', 'ticket', ticket_id)
        return redirect('/tickets')

    html_code = "<h3>Creare Ticket Nou</h3>"
    html_code += "<form method='POST'>"
    html_code += "Titlu: <input type='text' name='title'><br>"
    html_code += "Descriere: <textarea name='description' rows='4' cols='30'></textarea><br>"
    html_code += "Severitate: <select name='severity'><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select><br><br>"
    html_code += "<input type='submit' value='Salveaza Ticket'>"
    html_code += "</form><br><a href='/tickets'>Inapoi la lista</a>"
    return html_code

@app.route('/tickets/<int:ticket_id>')
def view_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # FIX 6: IDOR (Insecure Direct Object Reference)
    # Acum verificam in query ca ticketul ii apartine utilizatorului (AND owner_id = ?)
    cursor.execute("SELECT title, description, severity, status, owner_id FROM tickets WHERE id = ? AND owner_id = ?", 
                   (ticket_id, session['user_id']))
    ticket = cursor.fetchone()
    conn.close()

    if not ticket:
        return "Eroare: Ticket inexistent sau acces neautorizat. <a href='/tickets'>Inapoi</a>"

    title, description, severity, status, owner_id = ticket
    
    # FIX 9: Stored XSS
    # Folosim html.escape pentru a sanitiza
    safe_title = html.escape(str(title))
    safe_desc = html.escape(str(description))
    safe_status = html.escape(str(status))
    safe_sev = html.escape(str(severity))

    html_code = f"<h3>Ticket #{ticket_id} - {safe_title}</h3>"
    html_code += f"<p><b>Proprietar (User ID):</b> {owner_id}</p>"
    html_code += f"<p><b>Status:</b> {safe_status} | <b>Severitate:</b> {safe_sev}</p>"
    html_code += f"<p><b>Descriere:</b> {safe_desc}</p>"
    html_code += "<br><a href='/tickets'>Inapoi la lista</a>"
    
    return html_code

@app.route('/tickets/search', methods=['GET'])
def search_tickets():
    if 'user_id' not in session:
        return redirect('/login')

    search_query = request.args.get('q', '')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # SQL Injection
        # Folosim parametrizare sigura (?) pentru WHERE LIKE
        # Adaugam si protectia IDOR sa poata cauta doar in tichetele lui
        cursor.execute("SELECT id, title, severity, status, owner_id FROM tickets WHERE title LIKE ? AND owner_id = ?", 
                       (f"%{search_query}%", session['user_id']))
        results = cursor.fetchall()
    except sqlite3.Error as e:
        # FIX 8: SQL Error Disclosure
        # Nu mai afisam {e}, ci un mesaj generic 
        return "<h3>Eroare generica de procesare. Va rugam reincercati.</h3><br><a href='/tickets'>Inapoi</a>"
    finally:
        conn.close()

    # Sanitizam si termenul cautat 
    safe_query = html.escape(search_query)
    html_code = f"<h3>Rezultate cautare pentru: {safe_query}</h3>"
    
    if not results:
        html_code += "<p>Nu am gasit niciun ticket.</p>"
    else:
        html_code += "<table border='1'><tr><th>ID</th><th>Titlu</th><th>Proprietar</th><th>Status</th></tr>"
        for r in results:
            safe_t = html.escape(str(r[1]))
            safe_s = html.escape(str(r[3]))
            html_code += f"<tr><td>{r[0]}</td><td>{safe_t}</td><td>User {r[4]}</td><td>{safe_s}</td></tr>"
        html_code += "</table>"
        
    html_code += "<br><a href='/tickets'>Inapoi la lista de tichete</a>"
    return html_code

if __name__ == '__main__':
    app.run(debug=True, port=5000)