# app.py (fixed version)
import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, g

app = Flask(__name__)
app.secret_key = 'traveloop_secret_key_change_in_production'

DATABASE = 'traveloop.db'

# ---------------------------
# Database Helpers
# ---------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            photo TEXT,
            language TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Trips table
        cursor.execute('''CREATE TABLE IF NOT EXISTS trips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            cover_photo TEXT,
            is_public BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )''')
        
        # Stops (cities) table
        cursor.execute('''CREATE TABLE IF NOT EXISTS stops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trip_id INTEGER NOT NULL,
            city_name TEXT NOT NULL,
            country TEXT,
            cost_index INTEGER DEFAULT 1,
            popularity INTEGER DEFAULT 0,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            order_index INTEGER DEFAULT 0,
            FOREIGN KEY (trip_id) REFERENCES trips (id) ON DELETE CASCADE
        )''')
        
        # Activities table
        cursor.execute('''CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stop_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            activity_type TEXT,
            cost REAL DEFAULT 0,
            duration_hours INTEGER DEFAULT 1,
            activity_date DATE,
            time_of_day TEXT,
            image_url TEXT,
            FOREIGN KEY (stop_id) REFERENCES stops (id) ON DELETE CASCADE
        )''')
        
        # Packing items table
        cursor.execute('''CREATE TABLE IF NOT EXISTS packing_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trip_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            is_packed BOOLEAN DEFAULT 0,
            FOREIGN KEY (trip_id) REFERENCES trips (id) ON DELETE CASCADE
        )''')
        
        # Trip notes table
        cursor.execute('''CREATE TABLE IF NOT EXISTS trip_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trip_id INTEGER NOT NULL,
            stop_id INTEGER,
            note TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (trip_id) REFERENCES trips (id) ON DELETE CASCADE,
            FOREIGN KEY (stop_id) REFERENCES stops (id) ON DELETE CASCADE
        )''')
        
        # Saved destinations for user
        cursor.execute('''CREATE TABLE IF NOT EXISTS saved_destinations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            city_name TEXT NOT NULL,
            country TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )''')
        
        # City directory for search
        cursor.execute('''CREATE TABLE IF NOT EXISTS city_directory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            city_name TEXT UNIQUE,
            country TEXT,
            cost_index INTEGER,
            popularity INTEGER
        )''')
        
        # Insert sample cities if empty
        cursor.execute("SELECT COUNT(*) FROM city_directory")
        if cursor.fetchone()[0] == 0:
            sample_cities = [
                ('New York', 'USA', 5, 98), ('Paris', 'France', 5, 99), ('Tokyo', 'Japan', 4, 97),
                ('London', 'UK', 5, 96), ('Rome', 'Italy', 4, 95), ('Barcelona', 'Spain', 3, 94),
                ('Bangkok', 'Thailand', 2, 93), ('Istanbul', 'Turkey', 2, 92), ('Dubai', 'UAE', 4, 91),
                ('Singapore', 'Singapore', 4, 90), ('Los Angeles', 'USA', 4, 89), ('Amsterdam', 'Netherlands', 4, 88),
                ('Sydney', 'Australia', 4, 87), ('Berlin', 'Germany', 3, 86), ('Venice', 'Italy', 4, 85),
                ('Kyoto', 'Japan', 3, 84), ('Prague', 'Czechia', 2, 83), ('Vienna', 'Austria', 3, 82)
            ]
            for city in sample_cities:
                cursor.execute("INSERT OR IGNORE INTO city_directory (city_name, country, cost_index, popularity) VALUES (?, ?, ?, ?)", city)
        
        db.commit()

# ---------------------------
# Authentication Helpers
# ---------------------------
def hash_password(password):
    salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt

def verify_password(stored_password, provided_password):
    password_hash, salt = stored_password.split(':')
    return password_hash == hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000).hex()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to calculate date difference in days
def date_diff_in_days(date1, date2):
    d1 = datetime.strptime(date1, '%Y-%m-%d')
    d2 = datetime.strptime(date2, '%Y-%m-%d')
    return abs((d1 - d2).days)

# ---------------------------
# Routes
# ---------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and verify_password(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid email or password")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return render_template('signup.html', error="Email already registered")
        hashed = hash_password(password)
        db.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed))
        db.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    trips = db.execute('''
        SELECT t.*, 
               (SELECT COUNT(*) FROM stops WHERE trip_id = t.id) as stop_count
        FROM trips t 
        WHERE t.user_id = ? 
        ORDER BY t.start_date DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get popular cities for inspiration
    popular_cities = db.execute("SELECT city_name, country, popularity, cost_index FROM city_directory ORDER BY popularity DESC LIMIT 6").fetchall()
    
    # Budget highlights - upcoming trips total budget estimate (fixed to avoid DATEDIFF)
    upcoming = db.execute('''
        SELECT t.id, t.name, 
               COALESCE(SUM(a.cost), 0) as activities_cost,
               (julianday(t.end_date) - julianday(t.start_date) + 1) * 150 as stay_estimate
        FROM trips t
        LEFT JOIN stops s ON s.trip_id = t.id
        LEFT JOIN activities a ON a.stop_id = s.id
        WHERE t.user_id = ? AND t.start_date >= date('now')
        GROUP BY t.id
        ORDER BY t.start_date
        LIMIT 1
    ''', (session['user_id'],)).fetchone()
    
    budget_highlight = None
    if upcoming:
        budget_highlight = {
            'trip_name': upcoming['name'],
            'estimated_total': upcoming['activities_cost'] + (upcoming['stay_estimate'] or 0)
        }
    
    return render_template('dashboard.html', user=user, trips=trips, popular_cities=popular_cities, budget_highlight=budget_highlight)

@app.route('/trips')
@login_required
def my_trips():
    db = get_db()
    trips = db.execute('''
        SELECT t.*, 
               (SELECT COUNT(*) FROM stops WHERE trip_id = t.id) as stop_count,
               (SELECT COUNT(*) FROM packing_items WHERE trip_id = t.id) as packing_count
        FROM trips t 
        WHERE t.user_id = ? 
        ORDER BY t.start_date DESC
    ''', (session['user_id'],)).fetchall()
    return render_template('my_trips.html', trips=trips)

@app.route('/create_trip', methods=['GET', 'POST'])
@login_required
def create_trip():
    if request.method == 'POST':
        name = request.form['name']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        description = request.form.get('description', '')
        cover_photo = request.form.get('cover_photo', '')
        
        db = get_db()
        cursor = db.execute('''
            INSERT INTO trips (user_id, name, description, start_date, end_date, cover_photo)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], name, description, start_date, end_date, cover_photo))
        db.commit()
        trip_id = cursor.lastrowid
        return redirect(url_for('edit_trip', trip_id=trip_id))
    return render_template('create_trip.html')

@app.route('/trips/<int:trip_id>/edit')
@login_required
def edit_trip(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    stops = db.execute("SELECT * FROM stops WHERE trip_id = ? ORDER BY order_index, start_date", (trip_id,)).fetchall()
    
    # Get activities for each stop
    stops_with_activities = []
    for stop in stops:
        activities = db.execute("SELECT * FROM activities WHERE stop_id = ? ORDER BY activity_date, time_of_day", (stop['id'],)).fetchall()
        stop_dict = dict(stop)
        stop_dict['activities'] = activities
        stops_with_activities.append(stop_dict)
    
    # Get available cities for search
    cities = db.execute("SELECT city_name, country, cost_index, popularity FROM city_directory ORDER BY popularity DESC LIMIT 20").fetchall()
    
    return render_template('edit_trip.html', trip=trip, stops=stops_with_activities, cities=cities)

@app.route('/api/add_stop', methods=['POST'])
@login_required
def add_stop():
    data = request.json
    trip_id = data['trip_id']
    db = get_db()
    trip = db.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        return jsonify({'error': 'Trip not found'}), 404
    
    # Get max order_index
    max_order = db.execute("SELECT COALESCE(MAX(order_index), -1) as max FROM stops WHERE trip_id = ?", (trip_id,)).fetchone()['max']
    
    cursor = db.execute('''
        INSERT INTO stops (trip_id, city_name, country, cost_index, popularity, start_date, end_date, order_index)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (trip_id, data['city_name'], data.get('country', ''), data.get('cost_index', 3), 
          data.get('popularity', 0), data['start_date'], data['end_date'], max_order + 1))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Stop added'})

@app.route('/api/stop/<int:stop_id>', methods=['DELETE'])
@login_required
def delete_stop(stop_id):
    db = get_db()
    # Verify ownership via trip
    stop = db.execute('''
        SELECT s.id, t.user_id FROM stops s JOIN trips t ON s.trip_id = t.id WHERE s.id = ?
    ''', (stop_id,)).fetchone()
    if not stop or stop['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    db.execute("DELETE FROM stops WHERE id = ?", (stop_id,))
    db.commit()
    return jsonify({'message': 'Stop deleted'})

@app.route('/api/add_activity', methods=['POST'])
@login_required
def add_activity():
    data = request.json
    db = get_db()
    # Verify ownership via stop -> trip
    stop = db.execute('''
        SELECT s.id, t.user_id FROM stops s JOIN trips t ON s.trip_id = t.id WHERE s.id = ?
    ''', (data['stop_id'],)).fetchone()
    if not stop or stop['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    cursor = db.execute('''
        INSERT INTO activities (stop_id, name, description, activity_type, cost, duration_hours, activity_date, time_of_day)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (data['stop_id'], data['name'], data.get('description', ''), data.get('activity_type', ''),
          data.get('cost', 0), data.get('duration_hours', 1), data.get('activity_date'), data.get('time_of_day', '')))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Activity added'})

@app.route('/trips/<int:trip_id>/itinerary')
@login_required
def itinerary_view(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    
    stops = db.execute("SELECT * FROM stops WHERE trip_id = ? ORDER BY start_date", (trip_id,)).fetchall()
    
    # Build day-wise itinerary
    days = []
    current_date = datetime.strptime(trip['start_date'], '%Y-%m-%d').date()
    end_date = datetime.strptime(trip['end_date'], '%Y-%m-%d').date()
    
    while current_date <= end_date:
        day_info = {'date': current_date.strftime('%Y-%m-%d'), 'activities': [], 'city': None}
        for stop in stops:
            stop_start = datetime.strptime(stop['start_date'], '%Y-%m-%d').date()
            stop_end = datetime.strptime(stop['end_date'], '%Y-%m-%d').date()
            if stop_start <= current_date <= stop_end:
                day_info['city'] = stop['city_name']
                activities = db.execute('''
                    SELECT * FROM activities WHERE stop_id = ? AND activity_date = ?
                    ORDER BY time_of_day
                ''', (stop['id'], current_date.strftime('%Y-%m-%d'))).fetchall()
                day_info['activities'] = activities
                break
        days.append(day_info)
        current_date += timedelta(days=1)
    
    return render_template('itinerary.html', trip=trip, stops=stops, days=days)

@app.route('/trips/<int:trip_id>/budget')
@login_required
def budget_view(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    
    stops = db.execute("SELECT * FROM stops WHERE trip_id = ?", (trip_id,)).fetchall()
    
    total_activities_cost = 0
    stop_breakdown = []
    day_costs = {}
    
    # Calculate trip duration using julianday
    start = datetime.strptime(trip['start_date'], '%Y-%m-%d')
    end = datetime.strptime(trip['end_date'], '%Y-%m-%d')
    trip_days = (end - start).days + 1
    stay_cost_per_day = 150  # average hotel cost estimate
    meal_cost_per_day = 50
    transport_cost = 200  # estimated inter-city travel
    
    for stop in stops:
        activities = db.execute("SELECT SUM(cost) as total FROM activities WHERE stop_id = ?", (stop['id'],)).fetchone()
        stop_cost = activities['total'] or 0
        total_activities_cost += stop_cost
        stop_start = datetime.strptime(stop['start_date'], '%Y-%m-%d')
        stop_end = datetime.strptime(stop['end_date'], '%Y-%m-%d')
        stay_days = (stop_end - stop_start).days + 1
        stop_breakdown.append({
            'city': stop['city_name'],
            'activities': stop_cost,
            'stay': stay_days * stay_cost_per_day,
            'meals': stay_days * meal_cost_per_day,
            'total': stop_cost + (stay_days * stay_cost_per_day) + (stay_days * meal_cost_per_day)
        })
    
    total_stay_cost = trip_days * stay_cost_per_day
    total_meal_cost = trip_days * meal_cost_per_day
    total_cost = total_activities_cost + total_stay_cost + total_meal_cost + transport_cost
    avg_cost_per_day = total_cost / trip_days if trip_days > 0 else 0
    
    # Calculate daily costs for alerts
    current_date = start
    for i in range(trip_days):
        day_str = current_date.strftime('%Y-%m-%d')
        day_cost = meal_cost_per_day + stay_cost_per_day
        for stop in stops:
            stop_start = datetime.strptime(stop['start_date'], '%Y-%m-%d').date()
            stop_end = datetime.strptime(stop['end_date'], '%Y-%m-%d').date()
            if stop_start <= current_date.date() <= stop_end:
                day_activities = db.execute("SELECT SUM(cost) as total FROM activities WHERE stop_id = ? AND activity_date = ?", 
                                           (stop['id'], day_str)).fetchone()
                day_cost += (day_activities['total'] or 0)
                break
        day_costs[day_str] = day_cost
        current_date += timedelta(days=1)
    
    over_budget_days = [d for d, cost in day_costs.items() if cost > 350]  # alert threshold
    
    return render_template('budget.html', trip=trip, total_cost=total_cost, total_activities=total_activities_cost,
                          total_stay=total_stay_cost, total_meals=total_meal_cost, transport=transport_cost,
                          avg_per_day=avg_cost_per_day, stop_breakdown=stop_breakdown, over_budget_days=over_budget_days)

@app.route('/trips/<int:trip_id>/packing')
@login_required
def packing_list(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    items = db.execute("SELECT * FROM packing_items WHERE trip_id = ? ORDER BY category, name", (trip_id,)).fetchall()
    return render_template('packing.html', trip=trip, items=items)

@app.route('/api/packing/add', methods=['POST'])
@login_required
def add_packing_item():
    data = request.json
    db = get_db()
    trip = db.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (data['trip_id'], session['user_id'])).fetchone()
    if not trip:
        return jsonify({'error': 'Unauthorized'}), 403
    cursor = db.execute('''
        INSERT INTO packing_items (trip_id, name, category, is_packed)
        VALUES (?, ?, ?, 0)
    ''', (data['trip_id'], data['name'], data.get('category', 'Other')))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Item added'})

@app.route('/api/packing/<int:item_id>/toggle', methods=['POST'])
@login_required
def toggle_packing(item_id):
    db = get_db()
    item = db.execute('''
        SELECT pi.id, t.user_id FROM packing_items pi JOIN trips t ON pi.trip_id = t.id WHERE pi.id = ?
    ''', (item_id,)).fetchone()
    if not item or item['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    db.execute("UPDATE packing_items SET is_packed = NOT is_packed WHERE id = ?", (item_id,))
    db.commit()
    return jsonify({'message': 'Toggled'})

@app.route('/api/packing/<int:item_id>', methods=['DELETE'])
@login_required
def delete_packing_item(item_id):
    db = get_db()
    item = db.execute('''
        SELECT pi.id, t.user_id FROM packing_items pi JOIN trips t ON pi.trip_id = t.id WHERE pi.id = ?
    ''', (item_id,)).fetchone()
    if not item or item['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    db.execute("DELETE FROM packing_items WHERE id = ?", (item_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/trips/<int:trip_id>/notes')
@login_required
def trip_notes(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    stops = db.execute("SELECT id, city_name FROM stops WHERE trip_id = ?", (trip_id,)).fetchall()
    notes = db.execute('''
        SELECT n.*, s.city_name 
        FROM trip_notes n 
        LEFT JOIN stops s ON n.stop_id = s.id 
        WHERE n.trip_id = ? 
        ORDER BY n.created_at DESC
    ''', (trip_id,)).fetchall()
    return render_template('notes.html', trip=trip, notes=notes, stops=stops)

@app.route('/api/notes/add', methods=['POST'])
@login_required
def add_note():
    data = request.json
    db = get_db()
    trip = db.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (data['trip_id'], session['user_id'])).fetchone()
    if not trip:
        return jsonify({'error': 'Unauthorized'}), 403
    cursor = db.execute('''
        INSERT INTO trip_notes (trip_id, stop_id, note)
        VALUES (?, ?, ?)
    ''', (data['trip_id'], data.get('stop_id'), data['note']))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Note added'})

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    db = get_db()
    note = db.execute('''
        SELECT n.id, t.user_id FROM trip_notes n JOIN trips t ON n.trip_id = t.id WHERE n.id = ?
    ''', (note_id,)).fetchone()
    if not note or note['user_id'] != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    db.execute("DELETE FROM trip_notes WHERE id = ?", (note_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/trips/<int:trip_id>/share')
@login_required
def share_trip(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND user_id = ?", (trip_id, session['user_id'])).fetchone()
    if not trip:
        abort(404)
    # Toggle public status if requested
    if request.args.get('make_public') == '1':
        db.execute("UPDATE trips SET is_public = 1 WHERE id = ?", (trip_id,))
        db.commit()
        trip = db.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    
    public_url = url_for('public_itinerary', trip_id=trip_id, _external=True)
    return render_template('share.html', trip=trip, public_url=public_url)

@app.route('/public/trip/<int:trip_id>')
def public_itinerary(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ? AND is_public = 1", (trip_id,)).fetchone()
    if not trip:
        abort(404)
    stops = db.execute("SELECT * FROM stops WHERE trip_id = ? ORDER BY start_date", (trip_id,)).fetchall()
    days = []
    current_date = datetime.strptime(trip['start_date'], '%Y-%m-%d').date()
    end_date = datetime.strptime(trip['end_date'], '%Y-%m-%d').date()
    while current_date <= end_date:
        day_info = {'date': current_date.strftime('%Y-%m-%d'), 'activities': [], 'city': None}
        for stop in stops:
            stop_start = datetime.strptime(stop['start_date'], '%Y-%m-%d').date()
            stop_end = datetime.strptime(stop['end_date'], '%Y-%m-%d').date()
            if stop_start <= current_date <= stop_end:
                day_info['city'] = stop['city_name']
                activities = db.execute('''
                    SELECT * FROM activities WHERE stop_id = ? AND activity_date = ?
                    ORDER BY time_of_day
                ''', (stop['id'], current_date.strftime('%Y-%m-%d'))).fetchall()
                day_info['activities'] = activities
                break
        days.append(day_info)
        current_date += timedelta(days=1)
    return render_template('public_itinerary.html', trip=trip, stops=stops, days=days)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    saved = db.execute("SELECT * FROM saved_destinations WHERE user_id = ?", (session['user_id'],)).fetchall()
    
    if request.method == 'POST':
        name = request.form.get('name', user['name'])
        photo = request.form.get('photo', user['photo'])
        language = request.form.get('language', user['language'])
        db.execute("UPDATE users SET name = ?, photo = ?, language = ? WHERE id = ?", 
                  (name, photo, language, session['user_id']))
        db.commit()
        session['user_name'] = name
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user, saved_destinations=saved)

@app.route('/api/save_destination', methods=['POST'])
@login_required
def save_destination():
    data = request.json
    db = get_db()
    db.execute("INSERT OR IGNORE INTO saved_destinations (user_id, city_name, country) VALUES (?, ?, ?)",
              (session['user_id'], data['city_name'], data.get('country', '')))
    db.commit()
    return jsonify({'message': 'Saved'})

@app.route('/api/search_cities')
def search_cities():
    query = request.args.get('q', '')
    db = get_db()
    cities = db.execute('''
        SELECT city_name, country, cost_index, popularity 
        FROM city_directory 
        WHERE city_name LIKE ? OR country LIKE ?
        ORDER BY popularity DESC
        LIMIT 15
    ''', (f'%{query}%', f'%{query}%')).fetchall()
    return jsonify([dict(city) for city in cities])

@app.route('/api/search_activities')
def search_activities():
    activity_type = request.args.get('type', '')
    # Sample activity suggestions based on cities
    activities_db = [
        {'name': 'Eiffel Tower Tour', 'type': 'Sightseeing', 'cost': 30, 'duration': 2},
        {'name': 'Louvre Museum', 'type': 'Museum', 'cost': 25, 'duration': 3},
        {'name': 'Food Tour', 'type': 'Food', 'cost': 75, 'duration': 3},
        {'name': 'City Walking Tour', 'type': 'Sightseeing', 'cost': 20, 'duration': 2},
        {'name': 'Boat Cruise', 'type': 'Adventure', 'cost': 40, 'duration': 2},
        {'name': 'Cooking Class', 'type': 'Food', 'cost': 65, 'duration': 3},
        {'name': 'Mountain Hiking', 'type': 'Adventure', 'cost': 15, 'duration': 4},
        {'name': 'Wine Tasting', 'type': 'Food', 'cost': 50, 'duration': 2},
        {'name': 'Historical Museum', 'type': 'Museum', 'cost': 18, 'duration': 2},
        {'name': 'Bike Rental', 'type': 'Adventure', 'cost': 25, 'duration': 4},
    ]
    if activity_type:
        activities_db = [a for a in activities_db if a['type'].lower() == activity_type.lower()]
    return jsonify(activities_db)

# Admin routes - optional analytics dashboard
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    # Simple admin check - in production use proper auth
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        if request.form.get('password') == 'admin123':
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
    return '''
    <form method="post" style="margin:100px auto;width:300px;text-align:center">
        <h3>Admin Login</h3>
        <input type="password" name="password" placeholder="Enter admin password" style="width:100%;padding:8px;margin:10px 0">
        <button type="submit">Login</button>
    </form>
    '''

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    total_trips = db.execute("SELECT COUNT(*) as count FROM trips").fetchone()['count']
    total_activities = db.execute("SELECT COUNT(*) as count FROM activities").fetchone()['count']
    popular_cities = db.execute('''
        SELECT city_name, COUNT(*) as trip_count 
        FROM stops 
        GROUP BY city_name 
        ORDER BY trip_count DESC 
        LIMIT 10
    ''').fetchall()
    popular_activities = db.execute('''
        SELECT activity_type, COUNT(*) as count 
        FROM activities 
        WHERE activity_type IS NOT NULL AND activity_type != ''
        GROUP BY activity_type 
        ORDER BY count DESC
    ''').fetchall()
    trips_by_month = db.execute('''
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count 
        FROM trips 
        GROUP BY month 
        ORDER BY month DESC 
        LIMIT 6
    ''').fetchall()
    return render_template('admin_dashboard.html', total_users=total_users, total_trips=total_trips,
                          total_activities=total_activities, popular_cities=popular_cities,
                          popular_activities=popular_activities, trips_by_month=trips_by_month)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)