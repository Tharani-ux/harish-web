from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)  # Changed from name to match form
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Ensure password length is sufficient
    role = db.Column(db.String(50), nullable=False)
    profile_pic = db.Column(db.String(255), default="default.png")  # Profile pic column
    description = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password, password)

# Function to initialize the database
def init_db(app):
    """Initializes the database with the Flask app."""
    db.init_app(app)
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully.")
        except Exception as e:
            print(f"Error creating database tables: {e}")
