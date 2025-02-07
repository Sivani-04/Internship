from flask import Flask,jsonify, request
import psycopg2 # type: ignore # pip install psycopg2
from psycopg2 import sql # type: ignore
from flask_bcrypt import Bcrypt # type: ignore # pip install 
import jwt # pip install pyjwt
import datetime
from flask_jwt_extended import get_jwt_identity

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
            category_description TEXT NOT NULL,
            product_id INT NOT NULL
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
            product_price INT NOT NULL,
            category_id INT NOT NULL
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

@app.route('/delete-by-userid', methods=['DELETE'])
def delete_user():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "DELETE FROM users WHERE user_id = " + str(user_id)
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Successfully deleted the given user"})

@app.route('/get-user-by-userid', methods=['GET'])
def get_user_by_userid():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE user_id = "+ str(user_id)
    cursor.execute(query)
    user = cursor.fetchone()
    cursor.close()
    connection.close()
    if user:
        result = {
            "username": user [0],
            "password": user[1],
            "team": user[2]
        }
        return jsonify(result), 200
    else:
        return jsonify({"error": "user not found"}), 404

@app.route('/add-categories', methods=['POST'])
def register_categories():
    category_id = request.json['category_id']    
    category_name = request.json['category_name']
    category_description = request.json['category_description']
    product_id = request.json['product_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO categories (category_id, category_name, category_description, product_id) VALUES (%s, %s, %s, %s);
        """, (category_id, category_name, category_description, product_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "Category registered successfully"}),  201
    
@app.route('/add-products', methods=['POST'])
def register_products():
    product_id = request.json['product_id']    
    product_name = request.json['product_name']
    product_description = request.json['product_description']
    product_price = request.json['product_price']
    category_id = request.json['category_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO products (product_id, product_name, product_description, product_price, category_id) VALUES (%s, %s, %s, %s, %s);
        """, (product_id, product_name, product_description, product_price, category_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "Product registered successfully"}),  201

@app.route('/add-reviews', methods=['POST'])
def register_reviews():
    product_id = request.json['product_id']    
    user_id = request.json['user_id']
    review_text = request.json['review_text']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO reviews (product_id, user_id, review_text) VALUES (%s, %s, %s);
        """, (product_id, user_id, review_text))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "Review registered successfully"}),  201

@app.route('/get-reviews-by-userid', methods=['GET'])
def get_reviews_by_userid():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM reviews WHERE user_id = "+ str(user_id)
    cursor.execute(query)
    reviews = cursor.fetchall()
    cursor.close()
    connection.close()
    result = [{"user_id": each_review[0], "product_id": each_review[1], "review_text": each_review[2]}for each_review in reviews]
    return jsonify(result), 200

if __name__ == "__main__":
    app.run(debug=True)