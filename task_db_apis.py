from flask import Flask, jsonify, request, render_template
import psycopg2  # pip install psycopg2
from psycopg2 import sql
from flask_bcrypt import Bcrypt # pip install flask-bcrypt
import jwt # pip install pyjwt
import datetime

app = Flask(__name__) 

# Database connection configuration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = 'postgres'

# Your secret key to sign JWT tokens
SECRET_KEY = "this is a secret key this is a secret keyyyy!!!!"

# Function to get a database connection
def get_db_connection():
    connection = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return connection

# Create the 'tasks' table if it doesn't exist
def create_tasks_table_if_not_exists():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id SERIAL PRIMARY KEY,
            task_name TEXT NOT NULL,
            task_status TEXT NOT NULL,
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
            team TEXT NOT NULL
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

def check_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)

def decode_token(jwt_token):
    try:
        decoded_token_payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token_payload
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

@app.route('/create-task', methods=['POST'])
def create_task():
    task_name = request.json['task_name']
    task_status = request.json['task_status']
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO tasks (task_name, task_status, user_id) VALUES (%s, %s, %s);
        """, (task_name, task_status, user_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Task registered successfully."}), 201

@app.route('/register-user', methods=['POST'])
def register_user():
    username = request.json['username']
    team = request.json['team']
    password = request.json['password']
    hashed_password = encode_password(password)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            INSERT INTO users (username, password, team) VALUES (%s, %s, %s);
        """, (username, hashed_password, team))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "User registered successfully."}), 201

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

@app.route('/delete-by-user-id', methods=['DELETE'])
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
    return jsonify({"message": "Successfully deleted user"})


@app.route('/get-single-user', methods=['GET'])
def get_single_user():
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
            "user_id": user[0],
            "username": user[1],
            "team": user[3]
        }
        return jsonify(result), 200
    else:
        return jsonify({"error": "User not found"}), 404

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
    result = [{"task_id": each_task[0], "task_name": each_task[1], "task_status": each_task[2], "user_id": each_task[3]} for each_task in tasks]
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
    return jsonify({"message": "Successfully deleted task"})


@app.route('/get-user-tasks', methods=['GET'])
def get_user_tasks():
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
    result = [{"task_id": each_task[0], "task_name": each_task[1], "task_status": each_task[2], "user_id": each_task[3]} for each_task in tasks]
    return jsonify(result), 200

@app.route('/get-single-task', methods=['GET'])
def get_single_task():
    task_id = request.args.get('task_id')
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
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
            "task_name": task[1],
            "task_status": task[2],
            "user_id": task[3]
        }
        return jsonify(result), 200
    else:
        return jsonify({"error": "Task not found"}), 404

@app.route('/update-task', methods=['PUT'])
def update_task():
    task_id = request.json['task_id']
    task_status = request.json['task_status']
    
    jwt_token = request.headers['Authorization']
    decoded_token_payload = decode_token(jwt_token)
    user_id = decoded_token_payload['user_id']
    
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (task_id,))
    task = cursor.fetchone()

    if task is None:
        cursor.close()
        connection.close()
        return jsonify({"message": "Task not found"}), 404

    if task[3] != user_id:
        cursor.close()
        connection.close()
        return jsonify({"message": "Unauthorized. You cannot update this task."}), 403

    cursor.execute("""
        UPDATE tasks
        SET task_status = %s
        WHERE task_id = %s;
    """, (task_status, task_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message": "Task updated successfully."}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/create')
def create_task_view():
    return render_template('create_task.html')

@app.route('/get-tasks')
def get_user_tasks_view():
    return render_template('get_tasks.html')

if __name__ == '__main__': 
    app.run(debug=True) 