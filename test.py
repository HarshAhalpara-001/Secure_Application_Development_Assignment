from sqlmodel import select
from models import User, create_db, get_session

# Function to Add a Dummy User
def add_dummy_user():
    with get_session() as session:
        user = User(username="testuser1", email="test1@example.com", hashed_password="hashedpassword123")
        session.add(user)
        session.commit()
        print("✅ Dummy user added successfully!")

# Function to Fetch and Display Users
def fetch_users():
    with get_session() as session:
        users = session.exec(select(User)).all()
        if users:
            print("\n📌 Users in Database:")
            for user in users:
                print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}")
        else:
            print("⚠️ No users found in the database.")

# Run Tests
if __name__ == "__main__":
    create_db()      # Step 1: Initialize Database
    # add_dummy_user() # Step 2: Insert Dummy User
    fetch_users()    # Step 3: Fetch and Display Users
