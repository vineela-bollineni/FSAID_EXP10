from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
import bcrypt
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'yt5k9p2m8q1r4t6y9u2i5o0p3a7s2d8f1g4h6j9k2l5n8q1w4e7r0t3y6uiop')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# ✅ IN-MEMORY USERS (No database needed)
users_db = {}  # {email: {'password': hashed_password, 'created_at': timestamp}}
revoked_tokens = set()  # Token blacklist

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    """Register a new user"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if email in users_db:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Store user in memory
        users_db[email] = {
            'password': hash_password(password),
            'created_at': datetime.utcnow()
        }
        
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login and receive JWT tokens"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if email not in users_db or not verify_password(password, users_db[email]['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create tokens
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': email
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify({'access_token': access_token}), 200

@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    """Protected route requiring valid JWT"""
    current_user = get_jwt_identity()
    return jsonify({
        'message': 'Access granted to protected resource',
        'user': current_user,
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout by revoking the JWT token"""
    jti = get_jwt()['jti']
    revoked_tokens.add(jti)
    return jsonify({'message': 'Successfully logged out'}), 200

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if token is revoked"""
    jti = jwt_payload['jti']
    return jti in revoked_tokens

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization header required'}), 401

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
