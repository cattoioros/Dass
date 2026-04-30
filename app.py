import hashlib
import secrets
import sqlite3
from datetime import datetime
import base64

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

DB_NAME = "authx.db"

app = Flask(__name__)


app.config["SECRET_KEY"] = "cheie"


#Vulnerabilitatea 4.5 flag-urile HTTPONLY, Secure si samesite dezactivate
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None


def weak_hash(password):
    #Vulnerabilitatea 4.2
    #MD5 este un hashing slab, care nu cripteaza si nu foloseste salt
    return hashlib.md5(password.encode()).hexdigest()


def log_action(user_id, action, resource=None, resource_id=None):
    #Functia care face logging pentru o actiune
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""
        INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, action, resource, resource_id, request.remote_addr))
    conn.commit()
    conn.close()



@app.route('/')
def home():
    #pagina home a utilizatorului
    if 'user_id' in session:
        html = f"<h2>Salut, {session.get('email')}! (AuthX Portal)</h2>"
        html += "<ul>"
        html += "<li><a href='/tickets'>Vezi Tichetele Mele</a></li>"
        html += "<li><a href='/tickets/new'>Creeaza Ticket</a></li>"
        html += "<li><a href='/logout'>Deconectare</a></li>"
        html += "</ul>"
        return html
    
    html = "<h2>Bine ai venit la AuthX</h2>"
    html += "<a href='/login'>Autentificare (Login)</a> | <a href='/register'>Creare cont (Register)</a>"
    return html


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get("role", "USER")
        #vulnerabilitate 4.1 nu exista verificare pe complexitatea parolei si nici pe corectitudinea mail-ului
        if not email or not password:
            return "Eroare: Completati ambele campuri. <a href='/register'>Inapoi</a>"
        
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", 
                      (email, weak_hash(password), role))
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            log_action(user_id=user_id, action="REGISTER", resource='auth', )
            return "Cont creat cu succes! <a href='/login'>Mergi la Login</a>"
        except sqlite3.IntegrityError:
            return "Eroare: Emailul exista deja! <a href='/register'>Inapoi</a>"
        
    html = "<h3>Inregistrare</h3>"
    html += "<form method='POST'>"
    html += "Email: <input type='text' name='email'><br>"
    html += "Parola: <input type='password' name='password'><br>"
    html += "Rol:<select name='role'><option value='USER'>USER</option><option value='MANAGER'>MANAGER</option></select>"
    html += "<input type='submit' value='Register'>"
    html += "</form>"
    return html

@app.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            # Atacatorul afla ca emailul nu exist in baza de date
            return "Eroare: Utilizatorul nu exista in sistem! <a href='/login'>Inapoi</a>"
        user_id = user[0]
        stored_hash = user[1]

        if weak_hash(password) == stored_hash:
            session['user_id'] = user_id
            session['email'] = email
            log_action(user_id, 'LOGIN_SUCCESS', 'auth')
            return redirect('/')
        else:
            # Atacatorul afla ca emailul este valid, dar parola e gresita
            log_action(user_id, 'LOGIN_FAILED', 'auth')
            # Atacatorul poate incerca oricate variante posibile, nu exista rate-limiting
            return "Eroare: Parola gresita! <a href='/login'>Inapoi</a>"
        
    html = "<h3>Autentificare</h3>"
    html += "<form method='POST'>"
    html += "Email: <input type='text' name='email'><br>"
    html += "Parola: <input type='password' name='password'><br>"
    html += "<input type='submit' value='Login'>"
    html += "</form><br>"
    html += "<a href='/forgot-password'>Am uitat parola</a>"
    return html


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
        
        # VULNERABILITATE 4.6 Tokenul este doar mail-ul codificat in base64, iar acesta este unic, fara un timp de expirare
        predictable_token = base64.b64encode(email.encode()).decode()
        
        html = f"Daca emailul exista, s-a trimis link-ul: <br>"
        html += f"<a href='/reset-password?token={predictable_token}'>Link Resetare Parola</a>"
        return html

    html = "<h3>Resetare Parola</h3>"
    html += "<form method='POST'>"
    html += "Introdu email-ul contului: <input type='text' name='email'><br>"
    html += "<input type='submit' value='Trimite Link'>"
    html += "</form>"
    return html

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return "Eroare: Lipseste token-ul."
        
    try:
        # Decodam token-ul predictibil
        email = base64.b64decode(token).decode()
    except:
        return "Token invalid."

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (weak_hash(new_password), email))
        conn.commit()
        conn.close()
        
        return "Parola a fost schimbata! <a href='/login'>Login</a>"

    html = f"<h3>Resetare parola pentru: {email}</h3>"
    html += "<form method='POST'>"
    html += "Parola noua: <input type='password' name='new_password'><br>"
    html += "<input type='submit' value='Schimba'>"
    html += "</form>"
    return html





@app.route('/tickets', methods=['GET'])
def list_tickets():
    if 'user_id' not in session:
        return redirect('/login')
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, severity, status FROM tickets WHERE owner_id = ?", (session['user_id'],))
    tickets = cursor.fetchall()
    conn.close()
    
    html = f"<h3>Tichetele Tale (User: {session.get('email')})</h3>"
    
    # Formular pentru cautare
    html += "<form action='/tickets/search' method='GET'>"
    html += "Cauta ticket: <input type='text' name='q'> <input type='submit' value='Cauta'>"
    html += "</form><br>"

    html += "<table border='1'><tr><th>ID</th><th>Titlu</th><th>Status</th><th>Actiuni</th></tr>"
    for t in tickets:
        html += f"<tr><td>{t[0]}</td><td>{t[1]}</td><td>{t[3]}</td>"
        html += f"<td><a href='/tickets/{t[0]}'>Vezi</a> | <a href='/tickets/{t[0]}/edit'>Editeaza</a> | <a href='/tickets/{t[0]}/delete'>Sterge</a></td></tr>"
    html += "</table><br><a href='/'>Inapoi la meniu</a>"
    
    return html

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

    html = "<h3>Creare Ticket Nou</h3>"
    html += "<form method='POST'>"
    html += "Titlu: <input type='text' name='title'><br>"
    html += "Descriere: <textarea name='description' rows='4' cols='30'></textarea><br>"
    html += "Severitate: <select name='severity'><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select><br><br>"
    html += "<input type='submit' value='Salveaza Ticket'>"
    html += "</form><br><a href='/tickets'>Inapoi la lista</a>"
    return html

@app.route('/tickets/<int:ticket_id>')
def view_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABILITATE: IDOR (Insecure Direct Object Reference)
    # Backend-ul nu verifica daca ticket.owner_id == session['user_id'].
    cursor.execute("SELECT title, description, severity, status, owner_id FROM tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()

    if not ticket:
        return "Eroare: Ticket inexistent. <a href='/tickets'>Inapoi</a>"

    title, description, severity, status, owner_id = ticket
    
    # VULNERABILITATE: Stored XSS
    # Concatenam direct in html
    html = f"<h3>Ticket #{ticket_id} - {title}</h3>"
    html += f"<p><b>Proprietar (User ID):</b> {owner_id}</p>"
    html += f"<p><b>Status:</b> {status} | <b>Severitate:</b> {severity}</p>"
    html += f"<p><b>Descriere:</b> {description}</p>"
    html += "<br><a href='/tickets'>Inapoi la lista</a>"
    
    return html

@app.route('/tickets/<int:ticket_id>/edit', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABILITATE: IDOR pe Update. Oricine poate edita ticket-ul altcuiva
    cursor.execute("SELECT title, description, severity FROM tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()

    if not ticket:
        conn.close()
        return "Eroare: Ticket inexistent. <a href='/tickets'>Inapoi</a>"

    if request.method == 'POST':
        new_title = request.form.get('title')
        new_desc = request.form.get('description')
        new_severity = request.form.get('severity')
        
        cursor.execute("UPDATE tickets SET title = ?, description = ?, severity = ? WHERE id = ?", 
                       (new_title, new_desc, new_severity, ticket_id))
        conn.commit()
        conn.close()
        
        log_action(session['user_id'], 'UPDATE_TICKET', 'ticket', ticket_id)
        return redirect(f'/tickets/{ticket_id}')

    conn.close()
    title, description, severity = ticket

    html = f"<h3>Editare Ticket #{ticket_id}</h3>"
    html += "<form method='POST'>"
    html += f"Titlu: <input type='text' name='title' value='{title}'><br>"
    html += f"Descriere: <textarea name='description' rows='4' cols='30'>{description}</textarea><br>"
    
    html += "Severitate: <select name='severity'>"
    for option in ['LOW', 'MEDIUM', 'HIGH']:
        selected = "selected" if severity == option else ""
        html += f"<option value='{option}' {selected}>{option}</option>"
    html += "</select><br><br>"
    
    html += "<input type='submit' value='Actualizeaza Ticket'>"
    html += "</form><br><a href='/tickets'>Inapoi la lista</a>"
    return html

@app.route('/tickets/<int:ticket_id>/delete', methods=['GET'])
def delete_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABILITATE: IDOR pe Delete. Atacatorul poate sterge ticketele oricui daca ghiceste ID-ul.
    cursor.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    conn.commit()
    conn.close()
    
    log_action(session['user_id'], 'DELETE_TICKET', 'ticket', ticket_id)
    return redirect('/tickets')

@app.route('/tickets/search', methods=['GET'])
def search_tickets():
    if 'user_id' not in session:
        return redirect('/login')

    search_query = request.args.get('q', '')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABILITATE: SQL Injection 
    # Concatenam input-ul direct in query in loc sa folosim query parametrizat (?, ?)
    sql_query = f"SELECT id, title, severity, status, owner_id FROM tickets WHERE title LIKE '%{search_query}%'"
    
    try:
        cursor.execute(sql_query)
        results = cursor.fetchall()
    except sqlite3.Error as e:
        # Afisam eroarea SQL nativa pe ecran (alta vulnerabilitate - Information Disclosure)
        return f"<h3>Eroare Baza de date:</h3><p>{e}</p><br><a href='/tickets'>Inapoi</a>"
    finally:
        conn.close()

    html = f"<h3>Rezultate cautare pentru: {search_query}</h3>"
    
    if not results:
        html += "<p>Nu am gasit niciun ticket.</p>"
    else:
        html += "<table border='1'><tr><th>ID</th><th>Titlu</th><th>Proprietar</th><th>Status</th></tr>"
        for r in results:
            html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>User {r[4]}</td><td>{r[3]}</td></tr>"
        html += "</table>"
        
    html += "<br><a href='/tickets'>Inapoi la lista de tichete</a>"
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5000)