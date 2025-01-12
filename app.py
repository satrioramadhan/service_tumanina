from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
import os
from dotenv import load_dotenv
import requests
from datetime import timedelta

# Load environment variables
load_dotenv()

# App Config
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)  # Token berlaku 30 hari
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=60) 

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    __tablename__ = 'users_apk'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
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

# Utility function for user-friendly error messages
def format_error_message(exception):
    error_message = str(exception).lower()
    if "invalid_request_error" in error_message:
        return "Permintaan tidak valid. Silakan periksa kembali data Anda."
    elif "organization_restricted" in error_message:
        return "Akses ke API dibatasi. Silakan hubungi pengembang."
    elif "password lama salah" in error_message:
        return "Password lama salah. Pastikan password lama Anda benar."
    elif "email sudah digunakan" in error_message:
        return "Email ini sudah digunakan oleh pengguna lain. Silakan gunakan email yang berbeda."
    elif "token tidak ditemukan" in error_message:
        return "Token tidak ditemukan. Silakan login ulang."
    elif "password baru harus memiliki minimal 8 karakter" in error_message:
        return "Password baru minimal harus memiliki 8 karakter."
    elif "pengguna tidak ditemukan" in error_message:
        return "Pengguna tidak ditemukan. Pastikan Anda sudah login."
    elif "gagal memproses ulasan di server lama" in error_message:
        return "Gagal memproses ulasan di server lama. Silakan coba lagi nanti."
    else:
        return "Terjadi kesalahan yang tidak diketahui. Silakan coba lagi nanti."

# Register Route
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if User.query.filter_by(email=email).first():
            raise Exception("Email sudah digunakan oleh pengguna lain.")

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"msg": "Pendaftaran berhasil. Selamat datang!"}), 201
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 400

# Login Route
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"msg": "Email tidak terdaftar. Silakan periksa kembali."}), 404

        if not bcrypt.check_password_hash(user.password, password):
            return jsonify({"msg": "Password salah. Silakan coba lagi."}), 401

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        return jsonify({
            "msg": "Login berhasil. Selamat datang kembali!",
            "token": access_token,
            "refresh_token": refresh_token
        }), 200
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 400

# Refresh Token Route
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user)
        return jsonify({"access_token": new_token}), 200
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 500

# Get User Info Route
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, user_id)

        if not user:
            raise Exception("Pengguna tidak ditemukan.")

        return jsonify({"username": user.username, "email": user.email}), 200
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 400

# Edit User Route
@app.route('/user', methods=['PUT'])
@jwt_required()
def edit_user():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, user_id)

        if not user:
            return jsonify({"msg": "Pengguna tidak ditemukan. Pastikan Anda sudah login."}), 404

        data = request.get_json()
        username = data.get('username', user.username)
        email = data.get('email', user.email)
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if User.query.filter(User.id != user_id, User.email == email).first():
            return jsonify({"msg": "Email ini sudah digunakan oleh pengguna lain. Silakan gunakan email yang berbeda."}), 400

        if old_password and new_password:
            if not bcrypt.check_password_hash(user.password, old_password):
                return jsonify({"msg": "Password lama Anda tidak sesuai. Silakan coba lagi."}), 400

            if len(new_password) < 8:
                return jsonify({"msg": "Password baru harus memiliki minimal 8 karakter."}), 400

            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_new_password

        user.username = username
        user.email = email
        db.session.commit()

        return jsonify({"msg": "Profil berhasil diperbarui."}), 200
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 500

# Delete User Route
@app.route('/user', methods=['DELETE'])
@jwt_required()
def delete_user():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, user_id)

        if not user:
            return jsonify({"msg": "Pengguna tidak ditemukan. Pastikan Anda sudah login dan mencoba kembali."}), 404

        db.session.delete(user)
        db.session.commit()
        return jsonify({"msg": "Akun berhasil dihapus."}), 200
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 500

# Submit Sentiment Route
@app.route('/sentiment', methods=['POST'])
@jwt_required()
def submit_sentiment():
    try:
        data = request.get_json()
        nama = data.get('nama')
        review = data.get('review')

        if not nama or not review:
            return jsonify({"msg": "Nama dan ulasan wajib diisi."}), 400

        web_lama_url = "https://tumanina.me/sentimen/add_review"
        payload = {
            "name": nama,
            "text": review
        }

        response = requests.post(web_lama_url, json=payload)
        if response.status_code == 200:
            return jsonify({"msg": "Ulasan berhasil dikirim.", "detail": response.json()}), 200
        else:
            return jsonify({"msg": f"Gagal memproses ulasan. Status: {response.status_code}."}), 502
    except Exception as e:
        return jsonify({"msg": format_error_message(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)