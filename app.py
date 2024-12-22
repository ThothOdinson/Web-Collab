from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    progress = db.Column(db.String(500), default="")  # Track progress as a JSON string

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return render_template('dashboard.html', username=user.username, progress=user.progress)
        session.pop('user_id', None)  # Remove invalid session
    return render_template('index.html')

@app.route('/sales')
def sales():
    items = [
        {"name": "Microcenter", "link": "https://www.microcenter.com"},
        {"name": "Microsoft", "link": "https://www.microsoft.com"},
        {"name": "Amazon", "link": "https://www.amazon.com"},
        {"name": "Newlife Collab Custom PCs", "link": "/custom-pcs"}
    ]
    return render_template('webHTMLsales-1.html', items=items)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required!')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required!')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

@app.route('/update_progress', methods=['POST'])
def update_progress():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            new_progress = request.form['progress']  # Example: JSON data like {"topic": "complete"}
            user.progress = new_progress
            db.session.commit()
            flash('Progress updated!')
            return redirect(url_for('home'))
    flash('You need to log in to update progress!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()  # Ensure the database tables are created
    app.run(debug=True)
