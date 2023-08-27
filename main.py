from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
import bcrypt
import jwt
import datetime

app = FastAPI()

# Enable CORS
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
@app.post('/signup')
async def signup(data: dict):
    employee_id = data['employee_id']
    full_name = data['full_name']
    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    cursor = db.cursor()
    query = "INSERT INTO users (employee_id, full_name, hashed_password) VALUES (%s, %s, %s)"
    values = (employee_id, full_name, hashed_password.decode('utf-8'))
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    return {"message": "User signed up successfully"}

@app.post('/login')
async def login(data: dict):
    employee_id = data['employee_id']
    password = data['password']
    
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM users WHERE employee_id = %s"
    values = (employee_id,)
    cursor.execute(query, values)
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password'].encode('utf-8')):
        payload = {
            'user_id': user['id'],  # Include the user's ID in the payload
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        return {"token": token, "user_id": user['id']}  # Return the user ID along with the token
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


# Endpoint to get all users
@app.get('/get_all_users')
async def get_all_users():
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM users"
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    return users

# Endpoint to delete a user
@app.delete('/delete_user/{user_id}')
async def delete_user(user_id: int):
    cursor = db.cursor()
    query = "DELETE FROM users WHERE id = %s"
    values = (user_id,)
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    return {"message": "User deleted successfully"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# Protected endpoint example
@app.get('/protected')
async def protected_endpoint(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        # Perform actions based on the user using payload['user_id']
        return {"message": "This is a protected endpoint"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.post('/post_wall_message')
async def post_wall_message(data: dict):
    poster_id = data['poster_id']
    receiver_id = data['receiver_id']
    content = data['content']
    
    cursor = db.cursor()
    query = "INSERT INTO wall_posts (poster_id, receiver_id, content) VALUES (%s, %s, %s)"
    values = (poster_id, receiver_id, content)
    cursor.execute(query, values)
    db.commit()
    cursor.close()
    
    return {"message": "Message posted on user's wall successfully"}

# Endpoint for retrieving wall messages for a specific user
@app.get('/get_user_wall_messages/{user_id}')
async def get_user_wall_messages(user_id: int):
    cursor = db.cursor(dictionary=True)
    query = """
        SELECT wp.*, u.full_name AS poster_full_name
        FROM wall_posts wp
        INNER JOIN users u ON wp.poster_id = u.id
        WHERE wp.receiver_id = %s
    """
    values = (user_id,)
    cursor.execute(query, values)
    wall_messages = cursor.fetchall()
    cursor.close()
    return wall_messages

# Endpoint to delete a user's own message from another user's wall
@app.post('/delete_own_wall_message')
async def delete_own_wall_message(data: dict):
    message_id = data['message_id']
    poster_id = data['poster_id']
    receiver_id = data['receiver_id']
    
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM wall_posts WHERE id = %s AND poster_id = %s AND receiver_id = %s"
    values = (message_id, poster_id, receiver_id)
    cursor.execute(query, values)
    message = cursor.fetchone()
    
    if message:
        delete_query = "DELETE FROM wall_posts WHERE id = %s"
        delete_values = (message_id,)
        cursor.execute(delete_query, delete_values)
        db.commit()
        cursor.close()
        return {"message": "Message deleted successfully"}
    else:
        cursor.close()
        raise HTTPException(status_code=401, detail="Message not found or you are not authorized")
# Endpoint for user logout
@app.post('/logout')
async def logout(data: dict):
    user_id = data['user_id']
 
    # Perform any necessary actions related to logging out
    
    return {"message": "Logged out successfully"}

# Endpoint to get wall messages for the current user
@app.get('/get_current_user_wall_messages')
async def get_current_user_wall_messages(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    try:
        token = authorization.split()[1]  # Assuming "Bearer token" format
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = payload['user_id']

        cursor = db.cursor(dictionary=True)
        query = "SELECT * FROM wall_posts WHERE receiver_id = %s"
        values = (user_id,)
        cursor.execute(query, values)
        wall_messages = cursor.fetchall()
        cursor.close()
        return wall_messages
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
