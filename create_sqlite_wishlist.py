import sqlite3

def create_wishlist_table():
    """Create the wishlist table in SQLite database."""
    try:
        conn = sqlite3.connect('luxeshop.db')
        cursor = conn.cursor()
        
        # Create wishlist table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id)
        )
        ''')
        
        conn.commit()
        print("Wishlist table created successfully in SQLite!")
        return True
        
    except sqlite3.Error as e:
        print(f"Error creating wishlist table: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Creating wishlist table in SQLite...")
    if create_wishlist_table():
        print("Successfully set up wishlist table in SQLite!")
    else:
        print("Failed to set up wishlist table. Please check the error messages above.")
