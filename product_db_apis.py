from flask import Flask,jsonify, request
import psycopg2 # type: ignore # pip install psycopg2
from psycopg2 import sql # type: ignore
from flask_bcrypt import Bcrypt # type: ignore # pip install 
import jwt # pip install pyjwt
import datetime

app = Flask(__name__)

#Database connection configuaration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = 'POSTGRESQL'

# Your secret key to sign JWT tokens
SECRET_KEY = "this is a secret key this is a secret keyyyy!!!!"

# Function to get a database connection
def get_db_connection():
    connection = psycopg2.connect(
        host = DB_HOST,
        database = DB_NAME, 
        user = DB_USER,
        password = DB_PASSWORD
    )
    return connection

# Create the 'users' table if it doesn't exist
def create_users_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

# Create the 'categories' table if it doesn't exist
def create_categories_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            category_id SERIAL PRIMARY KEY,
            category_name TEXT NOT NULL UNIQUE,
            category_description TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

# Create the 'products' table if it doesn't exist
def create_products_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id SERIAL PRIMARY KEY,
            product_name TEXT NOT NULL UNIQUE,
            product_description TEXT NOT NULL,
            product_price INT NOT NULL       
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

# Create the 'reviews' table if it doesn't exist
def create_reviews_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            user_id SERIAL PRIMARY KEY,
            product_id INT NOT NULL,
            review_text TEXT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

create_users_table_if_not_exists()
create_categories_table_if_not_exists()
create_products_table_if_not_exists()
create_reviews_table_if_not_exists()

bcrypt = Bcrypt()

def encode_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(hashed_password,password):
    return bcrypt.check_password_hash(hashed_password, password)

def decode_token(jwt_token):
    try:
        decoded_token_payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token_payload
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

@app.route('/register-users', methods=['POST'])
def register_user():
    user_id = request.json['user_id']
    username = request.json['username']
    password = request.json['password']
    hashed_password = encode_password(password)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO users (user_id, username, password) VALUES (%s, %s, %s);
        """, (user_id, username, hashed_password))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "User registered successfully"}),  201

@app.route('/login', methods=['POST'])
def login_user():
    username = request.json['username']
    password = request.json['password']
    connection = get_db_connection()
    cursor = connection.cursor()
    # Check if the username exists
    cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
    user = cursor.fetchone()
    category = cursor.fetchone()
    # If the user does not exist
    if user is None:
        return jsonify({"message": "Invalid username or password."}), 401
    stored_hashed_password = user[2]
    # Compare the stored hashed password with the provided password
    if not check_password(stored_hashed_password, password):
        return jsonify({"message": "Invalid username or password."}), 401
    payload = {
        'username': username,
        'user_id': user[0],
        'category_id': category[0], # type: ignore
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration time
    }
    # Generate the token
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    cursor.close()
    connection.close()
    return jsonify({
        "message": "Login successful.",
        "token": token
    }), 200

@app.route('/add-categories', methods=['POST'])
def register_categories():
    category_id = request.json['category_id']    
    category_name = request.json['category_name']
    category_description = request.json['category_description']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO categories (category_id, category_name, category_description) VALUES (%s, %s, %s);
        """, (category_id, category_name, category_description))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "User registered successfully"}),  201

@app.route('/get-category-by-categoryid', methods=['GET'])
def get_category_by_categoryid():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    category_id = decoded_token_payload['category_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM categories WHERE category_id = "+ str(category_id)
    cursor.execute(query)
    category = cursor.fetchone()
    cursor.close()
    connection.close()
    if category:
        result = {
            "category_id": category[0],
            "category_name": category[1],
            "category_description": category[2]
        }
        return jsonify(result), 200
    else:
        return jsonify({"error": "user not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
