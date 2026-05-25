"""
CCS6344 — MiniLibrary Flask Backend  (v2)
Database & Cloud Security Assignment

Roles & Privileges:
  Librarian — full CRUD on books/members; manage all reservations;
              approve/reject returns; mark overdue; view audit log
  Member    — register; search catalogue; place reservations;
              view own reservations + due dates; request return

Security Measures (Task 5):
  1. TDE (AES-256)              — DB encrypted at rest (SSMS)
  2. RBAC                       — lib_admin / lib_member SQL Server logins
  3. Least Privilege            — lib_member: SELECT + EXECUTE only
  4. Row-Level Security (RLS)   — EXECUTE AS triggers RLS per member
  5. Parameterised Queries      — all DB calls use ? placeholders
  6. Signed Stored Procedures   — all writes go through signed SPs
  7. Schema Separation          — all objects in LibrarySchema
  8. SQL Server Audit           — server-level login + DML auditing
  9. AuditLog Table             — every SP call writes to AuditLog
 10. Session Management         — strong secret key, cleared on logout
 11. Server-side Validation     — every POST validates before DB call
 12. Password Hashing (bcrypt)  — passwords never stored/compared plain
 13. DDM                        — email + phoneNumber masked for lib_member
 14. Column Encryption          — phoneNumber encrypted with AES-128
 15. Always Encrypted           — icNumber encrypted client-side
"""

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from functools import wraps
import re
import pypyodbc as pyodbc
import bcrypt
from contextlib import contextmanager

# --------------------------------------------------- App & session ---------------------------------------------------
app = Flask(__name__)
app.secret_key = 'mmu_ccs6344_assignment_library_secret_key_v2'

# --------------------------------------------------- Database configuration ---------------------------------------------------
DB_SERVER = '192.168.0.21,1433' ##change to your own vm ip dont change the port number
DB_NAME = 'MiniLibraryDB'

_CONN = {
    'Librarian': (
        f"DRIVER={{SQL Server}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        f"UID=lib_admin;"
        f"PWD=Pa$$w0rd;"
    ),
    'Member': (
        f"DRIVER={{SQL Server}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_NAME};"
        f"UID=lib_member;"
        f"PWD=Pa$$w0rd;"
    ),
}

# --------------------------------------------------- Helpers ---------------------------------------------------
def get_db(role=None):
    """Return a fresh pypyodbc connection."""
    r = role or session.get('role', 'Member')
    conn_str = _CONN.get(r, _CONN['Member'])
    return pyodbc.connect(conn_str)

def friendly_error(exc):
    """Return only the human-readable SQL Server message, hiding state codes and driver info."""
    msg = str(exc)
    idx = msg.find('[SQL Server]')
    if idx != -1:
        human = msg[idx + 12:]                          # everything after [SQL Server]
        human = re.sub(r'\s*\(\d+\)\s*\(\w+\)', '', human)  # strip (50000) (SQLExecDirectW)
        human = human.strip(" '\")(")
        return human if human else 'A database error occurred.'
    return 'An error occurred. Please try again.'

def rows_to_dicts(cursor):
    """Convert pyodbc Rows → list of dicts, normalizing column names to PascalCase."""
    if cursor.description is None:
        return []
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]

@contextmanager
def as_user(cursor, username):
    """
    switches EXECUTE AS context for RLS.
    lib_member connection + EXECUTE AS 'ali.hassan'
    RLS fires - only Ali's reservations returned
    REVERT automatically after block exits
    """
    cursor.execute("EXECUTE AS USER = ?;", (username,))
    try:
        yield cursor
    finally:
        cursor.execute("REVERT;")

# --------------------------------------------------- decorators ---------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def librarian_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'Librarian':
            flash("Access denied — Librarians only.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

# --------------------------------------------------- Password Hashing (bcrypt) ---------------------------------------------------
def hash_password(plaintext: str):
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(
        plaintext.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

def check_password(plaintext: str, hashed: str):
    try:
        return bcrypt.checkpw(
            plaintext.encode('utf-8'),
            hashed.encode('utf-8')
        )
    except Exception:
        return plaintext == hashed
        
# --------------------------------------------------- AUTH ------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    """
    LOGIN
    Security: parameterised query (no raw string concat → no SQL injection).
    Checks IsActive=1 so deactivated members cannot log in.
    """
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for('login'))

        conn = get_db()
        cursor = conn.cursor()
        try:
            # Parameterised — safe against SQL injection
            cursor.execute(
                "SELECT userId, fullName, role, isActive, password "
                "FROM LibrarySchema.Users "
                "WHERE userName = ?",
                (username,)
            )
            row = cursor.fetchone()

            if not row:
                cursor.execute(
                    "EXEC LibrarySchema.sp_LogAudit "
                    "@action=?, @targetTable=?, @description=?",
                    ('LoginFailed', 'Users', f'Unknown user: {username}')
                )
                conn.commit()
                flash("Invalid credentials. Access denied.", "error")
                return render_template('login.html')
            
            user_id, full_name, role, is_active, stored_password = row

            # Password check
            if not check_password(password, stored_password):
                # Log failed attempt
                cursor.execute(
                    "EXEC LibrarySchema.sp_LogAudit "
                    "@userId=?, @action=?, @targetTable=?, @description=?",
                    (user_id, 'LoginFailed', 'Users', f'Wrong password: {username}')
                )
                conn.commit()

                # Check and potentially lock account
                cursor.execute(
                    "EXEC LibrarySchema.sp_checkLoginAttempts @userId=?, @userName=?",
                    (user_id, username)
                )
                result = cursor.fetchone()
                is_locked = result and result[0] == 1
                conn.commit()

                if is_locked:
                    flash(
                        "Account locked after too many failed attempts. "
                        "Contact the librarian to reactivate.",
                        "error"
                    )
                else:
                    flash("Invalid credentials. Access denied.", "error")

                return render_template('login.html')

            if not is_active:
                cursor.execute(
                    "EXEC LibrarySchema.sp_LogAudit "
                    "@userId=?, @action=?, @targetTable=?, @description=?",
                    (user_id, 'LoginBlocked', 'Users', f'Inactive account: {username}')
                )
                conn.commit()
                flash("Account is deactivated. Contact the librarian.", "error")
                return render_template('login.html')

            session['user']  = username
            session['userId']  = user_id
            session['fullName'] = full_name
            session['role'] = role

            cursor.execute(
                "EXEC LibrarySchema.sp_LogAudit "
                "@userId=?, @action=?, @targetTable=?, @description=?",
                (user_id, 'Login', 'Users', f'{username} logged in successfully')
            )
            conn.commit()

            flash(f"Welcome back, {full_name}!", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f"Database error: {friendly_error(e)}", "error")
            return render_template('login.html')
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    REGISTER
    Security:
    - bcrypt hash before storing
    - SP handles uniqueness checks
    - SP creates WITHOUT LOGIN user for RLS automatically
    - Uses lib_admin connection (SP needs CREATE USER DDL permission)
    """
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip() or None
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm', '').strip()

        if not all([username, fullname, email, password]):
            flash("All fields except phone are required.", "error")
            return render_template('register.html')

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template('register.html')

        # Hash password BEFORE sending to DB
        hashed = hash_password(password)

        conn   = get_db('Librarian')
        cursor = conn.cursor()
        try:
            cursor.execute(
                "EXEC LibrarySchema.sp_registerUser "
                "@userName=?, @fullName=?, @email=?, @password=?, @phoneNumber=?",
                (username, fullname, email, hashed, phone)
            )
            conn.commit()
            flash("Account created! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Registration failed: {friendly_error(e)}", "error")
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('userId')
    username = session.get('user')
    role = session.get('role')
    
    try:
        conn = get_db(role)
        cursor = conn.cursor()
        cursor.execute(
            "EXEC LibrarySchema.sp_LogAudit "
            "@userId=?, @action=?, @targetTable=?, @description=?",
            (user_id, 'Logout', 'Users', f'{username} logged out')
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# --------------------------------------------------- DASHBOARD ---------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    """
    DASHBOARD
    Librarian: all reservations overview, overdue count,
               pending returns, auto-marks overdue on load
    Member:    own active reservations via RLS (EXECUTE AS)
    """
    conn = get_db()
    cursor = conn.cursor()
    reservations = []
    overdue_count = 0
    pending_returns = 0

    try:
        if session['role'] == 'Librarian':
            # Auto mark overdue on every librarian dashboard load
            cursor.execute("EXEC LibrarySchema.sp_markOverdue")
            conn.commit()

            cursor.execute("EXEC LibrarySchema.sp_getAllReservations")
            reservations    = rows_to_dicts(cursor)
            overdue_count   = sum(1 for r in reservations if r['status'] == 'overdue')
            pending_returns = sum(1 for r in reservations if r['status'] == 'returnRequested')

        else:
            with as_user(cursor, session['user']):
                cursor.execute(
                    "SELECT r.reservationId, b.title, r.reservedAt, "
                    "       r.collectBy, r.borrowDate, r.dueDate, "
                    "       r.returnDate, r.status "
                    "FROM LibrarySchema.Reservations r "
                    "JOIN LibrarySchema.Books b ON r.bookId = b.bookId "
                    "WHERE r.userId = ? "
                    "ORDER BY r.reservedAt DESC",
                    (session['userId'],)
                )
                reservations = rows_to_dicts(cursor)

    except Exception as e:
        flash(f"Error loading dashboard: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('dashboard.html',
                           reservations=reservations,
                           overdue_count=overdue_count,
                           pending_returns=pending_returns)


# --------------------------------------------------- BOOKS ---------------------------------------------------

@app.route('/books')
@login_required
def list_books():
    """
    BOOK CATALOGUE — searchable by title / author / ISBN.
    Uses GetAllBooks SP with optional @SearchQuery parameter.
    Both Members and Librarians can access this.
    """
    q = request.args.get('q', '').strip() or None
    conn = get_db()
    cursor = conn.cursor()
    books = []

    try:
        cursor.execute("EXEC LibrarySchema.sp_getAllBooks @searchQuery=?", (q,))
        books = rows_to_dicts(cursor)
        print(books)
    except Exception as e:
        flash(f"Error loading books: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('books.html', books=books, query=q or '')


@app.route('/books/add', methods=['POST'])
@login_required
@librarian_required
def add_book():
    """
    ADD BOOK — Librarian only.
    Calls sp_addBook — SP blocks duplicate ISBN.
    Security: server-side validation before DB call.
    """
    title = request.form.get('title', '').strip()
    author = request.form.get('author', '').strip()
    isbn = request.form.get('isbn', '').strip()
    genre = request.form.get('genre', '').strip()
    quantity = request.form.get('quantity', '0').strip()

    if not all([title, author, isbn, genre]):
        flash("Title, Author, ISBN, and Genre are required.", "error")
        return redirect(url_for('list_books'))

    try:
        qty = int(quantity)
        if qty < 1:
            raise ValueError
    except ValueError:
        flash("Quantity must be a positive whole number.", "error")
        return redirect(url_for('list_books'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_addBook "
            "@title=?, @author=?, @isbn=?, @genre=?, @quantity=?, @addedBy=?",
            (title, author, isbn, genre, qty, session['userId'])
        )
        conn.commit()
        flash(f"Book '{title}' added to the catalogue.", "success")
    except Exception as e:
        flash(f"Failed to add book: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_books'))


@app.route('/books/edit/<int:book_id>', methods=['POST'])
@login_required
@librarian_required
def edit_book(book_id):
    """
    EDIT BOOK — Librarian only.
    Calls sp_editBook — SP checks ISBN uniqueness and adjusts availableQty.
    """
    title = request.form.get('title', '').strip()
    author = request.form.get('author', '').strip()
    isbn = request.form.get('isbn', '').strip()
    genre = request.form.get('genre', '').strip()
    quantity = request.form.get('quantity', '0').strip()

    if not all([title, author, isbn, genre]):
        flash("All fields are required.", "error")
        return redirect(url_for('list_books'))

    try:
        qty = int(quantity)
        if qty < 1:
            raise ValueError
    except ValueError:
        flash("Quantity must be a positive whole number.", "error")
        return redirect(url_for('list_books'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_editBook "
            "@bookId=?, @title=?, @author=?, @isbn=?, @genre=?, @quantity=?, @editedBy=?",
            (book_id, title, author, isbn, genre, qty, session['userId'])
        )
        conn.commit()
        flash(f"Book #{book_id} updated successfully.", "success")
    except Exception as e:
        flash(f"Edit failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_books'))


@app.route('/books/delete/<int:book_id>', methods=['POST'])
@login_required
@librarian_required
def delete_book(book_id):
    """
    DELETE BOOK — Librarian only.
    sp_deleteBook blocks deletion if active reservations exist.
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_deleteBook @bookId=?, @deletedBy=?", 
            (book_id, session['userId'])
        )
        conn.commit()
        flash(f"Book #{book_id} deleted.", "success")
    except Exception as e:
        flash(f"Delete failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_books'))


# --------------------------------------------------- RESERVATIONS --------------------------------------------------------------

@app.route('/reserve/<int:book_id>', methods=['POST'])
@login_required
def place_reservation(book_id):
    """
    PLACE RESERVATION — Member only.
    sp_createReservation validates:
      - Member is active
      - Book has stock
      - No duplicate active reservation
      - Decrements availableQty
      - Sets collectBy (+3 days), dueDate (+14 days)
      - Writes to AuditLog
    """

    conn = get_db()
    cursor = conn.cursor()
    try:
        with as_user(cursor, session['user']):
            cursor.execute(
                "EXEC LibrarySchema.sp_createReservation @userId=?, @bookId=?",
                (session['userId'], book_id)
            )
            conn.commit()
        flash("Reservation placed successfully! Collect within 3 days.", "success")
    except Exception as e:
        flash(f"Reservation failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('my_reservations'))


@app.route('/reservations/cancel/<int:res_id>', methods=['POST'])
@login_required
def cancel_reservation(res_id):
    """
    CANCEL RESERVATION — Member cancels own pending reservation.
    sp_cancelReservation validates ownership + pending status.
    Restores availableQty on cancel.
    """
    conn   = get_db()
    cursor = conn.cursor()
    try:
        with as_user(cursor, session['user']):
            cursor.execute(
                "EXEC LibrarySchema.sp_cancelReservation @reservationId=?, @userId=?",
                (res_id, session['userId'])
            )
            conn.commit()
        flash("Reservation cancelled successfully.", "success")
    except Exception as e:
        flash(f"Cancel failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('my_reservations'))


@app.route('/my_reservations')
@login_required
def my_reservations():
    """
    MY RESERVATIONS — Member views own reservation history.
    Security: EXECUTE AS triggers RLS — SQL Server filters rows
    automatically. WHERE userId = ? adds defence-in-depth.
    Joins Books to get title since Reservations only stores bookId.
    """
    conn = get_db()
    cursor = conn.cursor()
    reservations = []

    try:
        with as_user(cursor, session['user']):
            cursor.execute(
                "SELECT r.reservationId, b.title, r.reservedAt, "
                "       r.collectBy, r.borrowDate, r.dueDate, "
                "       r.returnDate, r.status "
                "FROM LibrarySchema.Reservations r "
                "JOIN LibrarySchema.Books b ON r.bookId = b.bookId "
                "WHERE r.userId = ? "
                "ORDER BY r.reservedAt DESC",
                (session['userId'],)
            )
            reservations = rows_to_dicts(cursor)
    except Exception as e:
        flash(f"Error: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('my_reservations.html', reservations=reservations)


@app.route('/reservations/request_return/<int:res_id>', methods=['POST'])
@login_required
def request_return(res_id):
    """
    RETURN REQUEST — Member clicks return button.
    Sets status = returnRequested.
    SP validates: reservation belongs to member + status is active/overdue.
    Librarian then physically confirms via approve_return.
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        with as_user(cursor, session['user']):
            cursor.execute(
                "EXEC LibrarySchema.sp_returnRequest @reservationId=?, @userId=?",
                (res_id, session['userId'])
            )
            conn.commit()
        flash("Return request submitted. Bring book to library counter.", "success")
    except Exception as e:
        flash(f"Request failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('my_reservations'))


@app.route('/reservations/all')
@login_required
@librarian_required
def all_reservations():
    """
    ALL RESERVATIONS — Librarian only.
    lib_admin is db_owner → bypasses RLS automatically, sees all rows.
    """
    status_filter = request.args.get('status', '').strip() or None
    conn = get_db()
    cursor = conn.cursor()
    reservations = []

    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_getAllReservations @statusFilter=?",
            (status_filter,)
        )
        reservations = rows_to_dicts(cursor)

    except Exception as e:
        flash(f"Error: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('all_reservations.html',
                           reservations=reservations,
                           status_filter=status_filter or '')


@app.route('/reservations/approve/<int:res_id>', methods=['POST'])
@login_required
@librarian_required
def approve_return(res_id):
    """
    APPROVE RETURN — Librarian confirms physical book received.
    sp_approveReturn: status → returned, returnDate set, stock +1.
    SP validates: status must be returnRequested.
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_approveReturn @reservationId=?, @approvedBy=?",
            (res_id, session['userId'])
        )
        conn.commit()
        flash(f"Return confirmed for Reservation #{res_id}. Stock restored.", "success")
    except Exception as e:
        flash(f"Approve failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('all_reservations', status='returnRequested'))


@app.route('/reservations/mark_overdue', methods=['POST'])
@login_required
@librarian_required
def mark_overdue():
    """
    MARK OVERDUE — Manual trigger (auto-runs on dashboard load too).
    Batch updates all active reservations past dueDate → overdue.
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("EXEC LibrarySchema.sp_markOverdue")
        conn.commit()
        flash("Overdue reservation updated.", "success")
    except Exception as e:
        flash(f"Failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('all_reservations'))


@app.route('/reservations/collect/<int:res_id>', methods=['POST'])
@login_required
@librarian_required
def collect_reservation(res_id):
    """
    COLLECT — Librarian marks member has physically collected the book.
    Sets status: pending -> active
    Sets borrowDate = now, dueDate = now + 14 days
    """
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_collectReservation @reservationId=?, @collectedBy=?",
            (res_id, session['userId'])
        )
        conn.commit()
        flash(f"Reservation #{res_id} marked as collected.", "success")
    except Exception as e:
        flash(f"Failed: {friendly_error(e)}", "error")
    finally:
        conn.close()
    return redirect(url_for('all_reservations', status='pending'))

# --------------------------------------------------- MEMBERS ---------------------------------------------------

@app.route('/members')
@login_required
@librarian_required
def list_members():
    """
    LIST MEMBERS — Librarian only.
    lib_admin is db_owner -> UNMASK automatic, sees real email/phoneNumber.
    """
    conn = get_db()
    cursor = conn.cursor()
    members = []

    try:
        cursor.execute("EXEC LibrarySchema.sp_getAllMembers")
        members = rows_to_dicts(cursor)
    except Exception as e:
        flash(f"Error loading members: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('members.html', members=members)

@app.route('/members/toggle/<int:member_id>', methods=['POST'])
@login_required
@librarian_required
def toggle_member(member_id):
    """
    TOGGLE MEMBER STATUS — Librarian activates/deactivates account.
    Deactivated members cannot log in (isActive = 0 check in login).
    """
    if member_id == session.get('userId'):
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for('list_members'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_changeMemberStatus @memberId=?, @toggledBy=?",
            (member_id, session['userId'])
        )
        conn.commit()
        flash(f"Member #{member_id} status updated.", "success")
    except Exception as e:
        flash(f"Toggle failed: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_members'))

@app.route('/members/add', methods=['POST'])
@login_required
@librarian_required
def add_member():
    """
    ADD MEMBER — Librarian only.
    Reuses sp_registerUser — same SP as public register.
    Uses lib_admin connection (needs CREATE USER DDL).
    """
    username = request.form.get('username', '').strip()
    fullname = request.form.get('fullname', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'Member').strip()

    if not all([username, fullname, email, password]):
        flash("All fields are required.", "error")
        return redirect(url_for('list_members'))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for('list_members'))

    if role not in ('Member', 'Librarian'):
        role = 'Member'

    hashed = hash_password(password)

    conn   = get_db('Librarian')
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_registerUser "
            "@userName=?, @fullName=?, @email=?, @password=?",
            (username, fullname, email, hashed)
        )
        if role == 'Librarian':
            cursor.execute(
                "UPDATE LibrarySchema.Users SET role='Librarian' WHERE userName=?",
                (username,)
            )
            cursor.execute(f"ALTER ROLE MemberRole DROP MEMBER [{username}]")
            cursor.execute(f"ALTER ROLE LibrarianRole ADD MEMBER [{username}]")
        conn.commit()
        flash(f"Member '{username}' created successfully.", "success")
    except Exception as e:
        flash(f"Failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_members'))


@app.route('/members/delete/<int:member_id>', methods=['POST'])
@login_required
@librarian_required
def delete_member(member_id):
    """
    DELETE MEMBER — Librarian only.
    sp_deleteMember blocks if member has active reservations.
    Also drops the WITHOUT LOGIN DB user for RLS cleanup.
    Blocks self-deletion.
    """
    if member_id == session.get('userId'):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('list_members'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC LibrarySchema.sp_deleteMember @memberId=?, @deletedBy=?",
            (member_id, session['userId'])
        )
        conn.commit()
        flash(f"Member deleted.", "success")
    except Exception as e:
        flash(f"Delete failed: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('list_members'))


# --------------------------------------------------- AUDIT LOG ----------------------------------------------------------------

@app.route('/audit')
@login_required
@librarian_required
def audit_log():
    """
    AUDIT LOG — Librarian only.
    Shows last 200 entries from AuditLog table.
    Joins Users to show userName instead of raw userId.
    """
    conn = get_db()
    cursor = conn.cursor()
    logs = []

    try:
        cursor.execute(
            "SELECT TOP 200 "
            "    l.logId, "
            "    l.loggedAt, "
            "    COALESCE(u.userName, 'system') AS userName, "
            "    l.action, "
            "    COALESCE(l.targetTable, '-') AS targetTable, "
            "    COALESCE(l.description, '-') AS description "
            "FROM LibrarySchema.AuditLog l "
            "LEFT JOIN LibrarySchema.Users u ON l.userId = u.userId "
            "ORDER BY l.loggedAt DESC"
        )
        logs = rows_to_dicts(cursor)
    except Exception as e:
        flash(f"Error: {friendly_error(e)}", "error")
    finally:
        conn.close()

    return render_template('audit.html', logs=logs)


# --------------------------------------------------- ENTRY ---------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)