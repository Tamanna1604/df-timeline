import sqlite3

def list_tables(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # List all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables in the database:", tables)

    # For debugging, print the schema of each table
    for table in tables:
        table_name = table[0]
        print(f"\nSchema of {table_name}:")
        cursor.execute(f"PRAGMA table_info({table_name});")
        schema = cursor.fetchall()
        for column in schema:
            print(column)

    conn.close()

# Replace with your actual database path
list_tables("C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/History.db")

import os

db_path = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/History.db"

if not os.path.exists(db_path):
    print(f"Error: Database file '{db_path}' does not exist.")
elif os.path.getsize(db_path) == 0:
    print(f"Error: Database file '{db_path}' is empty.")
else:
    print(f"Database file '{db_path}' exists and is not empty. Proceeding...")
    # Proceed with querying the database here
