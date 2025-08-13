#!/usr/bin/env python3
"""
Setup script to create Supabase tables and fix database issues
"""

import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

def setup_supabase_tables():
    """Create the users table in Supabase"""
    try:
        # Initialize Supabase client
        SUPABASE_URL = os.getenv('SUPABASE_URL')
        SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')
        
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("❌ Error: Missing Supabase credentials in .env file")
            return False
            
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        # Create users table using SQL
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS public.users (
            id SERIAL PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        
        -- Enable Row Level Security
        ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
        
        -- Create policy to allow users to read their own data
        CREATE POLICY "Users can view own profile" ON public.users
            FOR SELECT USING (auth.uid()::text = id::text);
            
        -- Create policy to allow user registration
        CREATE POLICY "Enable insert for registration" ON public.users
            FOR INSERT WITH CHECK (true);
        """
        
        # Execute the SQL using the service role key for admin operations
        service_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
        if service_key:
            admin_client = create_client(SUPABASE_URL, service_key)
            result = admin_client.rpc('exec_sql', {'sql': create_table_sql}).execute()
            print("[SUCCESS] Supabase users table created successfully")
        else:
            print("[WARNING] No service role key found. You may need to create the table manually in Supabase dashboard")
            print("SQL to run in Supabase SQL editor:")
            print(create_table_sql)
        
        # Test the connection
        response = supabase.table('users').select('*').limit(1).execute()
        print("[SUCCESS] Supabase connection test successful")
        return True
        
    except Exception as e:
        print(f"[ERROR] Error setting up Supabase: {str(e)}")
        print("\nManual Setup Required:")
        print("1. Go to your Supabase dashboard")
        print("2. Navigate to SQL Editor")
        print("3. Run the following SQL:")
        print("""
        CREATE TABLE IF NOT EXISTS public.users (
            id SERIAL PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        """)
        return False

def test_sqlite_connection():
    """Test SQLite database connection"""
    try:
        import sqlite3
        conn = sqlite3.connect('luxeshop.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        table_exists = cursor.fetchone() is not None
        conn.close()
        
        if table_exists:
            print("[SUCCESS] SQLite database and users table exist")
        else:
            print("[INFO] SQLite users table not found - will be created on app start")
        return True
    except Exception as e:
        print(f"[ERROR] SQLite connection error: {str(e)}")
        return False

if __name__ == "__main__":
    print("Setting up LuxeShop Database...")
    print("=" * 50)
    
    # Test SQLite
    print("\nTesting SQLite Database:")
    test_sqlite_connection()
    
    # Setup Supabase
    print("\nSetting up Supabase Database:")
    setup_supabase_tables()
    
    print("\n" + "=" * 50)
    print("[SUCCESS] Database setup complete!")
    print("\nNext steps:")
    print("1. If Supabase setup failed, create the table manually in Supabase dashboard")
    print("2. Update your .env file with the correct database password if needed")
    print("3. Restart your Flask application")
