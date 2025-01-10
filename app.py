from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# App Config
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    __tablename__ = 'users_apk'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class InputReview(db.Model):
    __tablename__ = 'input_review'
    id_review = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(255), nullable=False)
    tanggal = db.Column(db.DateTime, default=db.func.current_timestamp())
    review = db.Column(db.Text, nullable=False)

# Register Route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"token": access_token}), 200

# Get User Info Route
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"username": user.username, "email": user.email}), 200

# Edit User Route (Update Username, Email, Password)
@app.route('/user', methods=['PUT'])
@jwt_required()
def edit_user():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    data = request.get_json()

    # Ambil data dari request
    username = data.get('username', user.username)  # Default ke username lama jika tidak diisi
    email = data.get('email', user.email)          # Default ke email lama jika tidak diisi
    old_password = data.get('old_password')        # Password lama
    new_password = data.get('new_password')        # Password baru

    # Cek apakah username atau email sudah digunakan oleh user lain
    if User.query.filter(User.id != user_id, User.username == username).first():
        return jsonify({"msg": "Username already taken"}), 400

    if User.query.filter(User.id != user_id, User.email == email).first():
        return jsonify({"msg": "Email already taken"}), 400

    # Jika user ingin update password
    if old_password and new_password:
        # Validasi password lama
        if not bcrypt.check_password_hash(user.password, old_password):
            return jsonify({"msg": "Old password is incorrect"}), 400

        # Hash password baru dan update
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_new_password

    # Update username dan email
    user.username = username
    user.email = email

    db.session.commit()
    return jsonify({"msg": "User updated successfully"}), 200

# Delete User Route
@app.route('/user', methods=['DELETE'])
@jwt_required()
def delete_user():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "User deleted successfully"}), 200

# Submit Sentiment Route


@app.route('/sentiment', methods=['POST'])
@jwt_required()
def submit_sentiment():
    user_id = get_jwt_identity()  # Ambil ID user dari JWT
    data = request.get_json()

    # Ambil data dari request JSON
    nama = data.get('nama')  # Nama user
    review = data.get('review')  # Review/sentimen

    # Validasi input
    if not nama or not review:
        return jsonify({"msg": "Nama dan review wajib diisi"}), 400

    # Kirim data ke endpoint web lama
    web_lama_url = "http://tumanina.me/sentimen/add_review"  # URL endpoint web lama
    payload = {
        "name": nama,
        "text": review
    }
    try:
        response = requests.post(web_lama_url, json=payload)  # Kirim JSON payload ke web lama
        if response.status_code == 200:
            return jsonify({"msg": "Sentimen berhasil diproses", "detail": response.json()}), 200
        else:
            return jsonify({"msg": "Gagal memproses sentimen di web lama", "error": response.text}), 500
    except Exception as e:
        return jsonify({"msg": "Error connecting to web lama", "error": str(e)}), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Initialize database
    app.run(debug=True, host="0.0.0.0", port=5000)
