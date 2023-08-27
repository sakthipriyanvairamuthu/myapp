from flask import Flask, request, jsonify
import mysql.connector
from flask_cors import CORS
import bcrypt
import jwt
import datetime

app = Flask(__name__)
CORS(app)
# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="S@kthib4u",
    database="your_database_name"
)

# Secret key for JWT token signing (keep this secret!)
secret_key = "your_secret_key"

# Endpoint for user sign-up
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    employee_id = data['employee_id']
    full_name = data['full_name']
    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    cursor = db.cursor()
    query = "INSERT INTO users (employee_id, full_name, hashed_password) VALUES (%s, %s, %s)"
    values = (employee_id, full_name, hashed_password.decode('utf-8'))  # Decode bytes to string
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    return jsonify({"message": "User signed up successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    employee_id = data['employee_id']
    password = data['password']
    
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM users WHERE employee_id = %s"
    values = (employee_id,)
    cursor.execute(query, values)
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password'].encode('utf-8')):
        # Generate a JWT token and send it as a response
        payload = {
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expiration
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Endpoint to get all users
@app.route('/get_all_users', methods=['GET'])
def get_all_users():
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM users"
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    return jsonify(users)

# Endpoint to delete a user
@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    cursor = db.cursor()
    query = "DELETE FROM users WHERE id = %s"
    values = (user_id,)
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    return jsonify({"message": "User deleted successfully"})


# Protected endpoint example
@app.route('/protected', methods=['GET'])
def protected_endpoint():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token missing"}), 401

    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        # Perform actions based on the user using payload['user_id']
        return jsonify({"message": "This is a protected endpoint"})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

# Endpoint for posting a message on a user's wall
@app.route('/post_wall_message', methods=['POST'])
def post_wall_message():
    data = request.json
    poster_id = data['poster_id']
    receiver_id = data['receiver_id']
    content = data['content']
    
    cursor = db.cursor()
    query = "INSERT INTO wall_posts (poster_id, receiver_id, content) VALUES (%s, %s, %s)"
    values = (poster_id, receiver_id, content)
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    
    return jsonify({"message": "Message posted on user's wall successfully"})

# Endpoint for retrieving wall messages for a specific user
@app.route('/get_user_wall_messages/<int:user_id>', methods=['GET'])
def get_user_wall_messages(user_id):
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM wall_posts WHERE receiver_id = %s"
    values = (user_id,)
    cursor.execute(query, values)
    wall_messages = cursor.fetchall()
    cursor.close()
    return jsonify(wall_messages)

# Endpoint for deleting a user's own message on another user's wall



@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    user_id = data['user_id']
 
    return jsonify({"message": "Logged out successfully"})

# Endpoint to delete a user's own message from another user's wall
@app.route('/delete_own_wall_message', methods=['POST'])
def delete_own_wall_message():
    data = request.json
    message_id = data['message_id']
    poster_id = data['poster_id']  # The user who posted the message
    receiver_id = data['receiver_id']  # The user whose wall the message is on
    
    # Check if the user is the owner of the message and the message is on the receiver's wall
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM wall_posts WHERE id = %s AND poster_id = %s AND receiver_id = %s"
    values = (message_id, poster_id, receiver_id)
    cursor.execute(query, values)
    message = cursor.fetchone()
    
    if message:
        # Delete the message
        delete_query = "DELETE FROM wall_posts WHERE id = %s"
        delete_values = (message_id,)
        cursor.execute(delete_query, delete_values)
        db.commit()
        cursor.close()
        return jsonify({"message": "Message deleted successfully"})
    else:
        cursor.close()
        return jsonify({"message": "Message not found or you are not authorized"}), 401


if __name__ == '__main__':
    app.run(debug=True)
