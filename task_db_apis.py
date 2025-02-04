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

# Create the 'tasks' table if it doesn't exist
def create_tasks_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id SERIAL PRIMARY KEY,
            task_title TEXT NOT NULL UNIQUE,
            task_description TEXT NOT NULL UNIQUE,
            user_id INT NOT NULL
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

# Create the 'users' table if it doesn't exist
def create_users_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            team TEXT NOT NULL UNIQUE
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

create_tasks_table_if_not_exists()
create_users_table_if_not_exists()

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

@app.route('/register-tasks', methods=['POST'])
def register_tasks():
    task_title = request.json['task_title']
    task_description = request.json['task_description']
    jwt_token = request.headers.get('Authorization')
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO tasks (task_title, task_description, user_id) VALUES (%s, %s, %s);
        """, (task_title, task_description, user_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify ({"message": "Task registered successfully"}),  201

@app.route('/register-users', methods=['POST'])
def register_user():
    user_id = request.json['user_id']
    username = request.json['username']
    team = request.json['team']
    password = request.json['password']
    hashed_password = encode_password(password)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO users (user_id, username, password,team) VALUES (%s, %s, %s, %s);
        """, (user_id, username, hashed_password,team))
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
    jwt_token = request.headers('Authorization')
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

@app.route('/get-all-tasks', methods=['GET'])
def get_all_tasks():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT * FROM tasks;
    """      
    )
    tasks = cursor.fetchall()
    cursor.close()
    connection.close()
    result = [{"task_id": each_task[0], "task_title": each_task[1], "task_description": each_task[2], "task_status": each_task[3]}for each_task in tasks]
    return jsonify(result), 200

@app.route('/delete-by-task-id', methods=['DELETE'])
def delete_task():
    task_id = request.args.get('task_id')
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "DELETE FROM tasks WHERE task_id = " + str(task_id) + " AND user_id = " + str(user_id)
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Successfully deleted given task"})

@app.route('/get-tasks-by-userid', methods=['GET'])
def get_tasks_by_userid():
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM tasks WHERE user_id = "+ str(user_id)
    cursor.execute(query)
    tasks = cursor.fetchall()
    cursor.close()
    connection.close()
    result = [{"task_id": each_task[0], "task_title": each_task[1], "task_description": each_task[2], "user_id": each_task[3]}for each_task in tasks]
    return jsonify(result), 200

@app.route('/get-single-task', methods=['GET'])
def get_single_task():
    task_id = request.args.get('task_id')
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    task_id = decoded_token_payload['task_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM tasks WHERE task_id = "+ str(task_id)
    cursor.execute(query)
    task = cursor.fetchone()
    cursor.close()
    connection.close()
    if task:
        result = {
            "task_id": task[0],
            "task_title": task[1],
            "task_description": task[2],
            "user_id": task[3]
        }
        return jsonify(result), 200
    else:
        return jsonify({"error": "Task not found"}), 404
if __name__ == '__main__':
    app.run(debug=True)