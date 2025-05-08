import sqlite3

# Connect to the database
try:
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    # Check if source_tool column already exists
    cursor.execute("PRAGMA table_info(app_vulnerabilities)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'source_tool' not in columns:
        # Add the source_tool column to app_vulnerabilities table
        cursor.execute('ALTER TABLE app_vulnerabilities ADD COLUMN source_tool TEXT')
        # Set a default value for existing records
        cursor.execute("UPDATE app_vulnerabilities SET source_tool = 'Unknown' WHERE source_tool IS NULL")
        print("Added source_tool column to app_vulnerabilities table and updated existing records successfully.")
    else:
        print("source_tool column already exists in app_vulnerabilities table.")

    # Commit the changes and close the connection
    conn.commit()

except sqlite3.Error as e:
    print(f"Database error: {str(e)}")

finally:
    conn.close()