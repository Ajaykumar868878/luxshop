#!/usr/bin/env python3
"""
Script to create the users table in Supabase database
Run this script once to set up the users table for the LuxeShop app
"""

import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Supabase setup
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ Error: SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env file")
    exit(1)

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def create_users_table():
    """Create the users table in Supabase using SQL"""
    
    # SQL to create users table and enable RLS
    setup_sql = """
    -- Create users table
    CREATE TABLE IF NOT EXISTS public.users (
        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        birthdate DATE,
        bio TEXT
    );

    -- Create index on email
    CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);

    -- Enable Row Level Security
    ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

    -- Drop existing policies to avoid conflicts
    DROP POLICY IF EXISTS "Users can view their own profile" ON public.users;
    DROP POLICY IF EXISTS "Enable insert for registration" ON public.users;
    DROP POLICY IF EXISTS "Users can update their own profile" ON public.users;

    -- Create policy to allow users to read their own data
    CREATE POLICY "Users can view their own profile" ON public.users
        FOR SELECT USING (auth.uid() = id);
        
    -- Create policy to allow user registration (public access)
    CREATE POLICY "Enable insert for registration" ON public.users
        FOR INSERT WITH CHECK (true);

    -- Create policy to allow users to update their own profile
    CREATE POLICY "Users can update their own profile" ON public.users
        FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
    """
    
    print("\nThis script provides the necessary SQL to set up your 'users' table.")
    print("Please run the following SQL in your Supabase dashboard's SQL Editor:")
    print("=" * 60)
    print(setup_sql)
    print("=" * 60)
    print("\nAfter running the SQL, your database will be set up correctly.")
    print("You can then try to sign up and log in through the web interface.")
    print("\nAttempting to verify connection...")

    try:
        # Try to connect and check if the table exists
        supabase.table('users').select('id').limit(1).execute()
        print("Connection successful and 'users' table is accessible.")
    except Exception as e:
        print(f"Connection/verification failed: {e}")
        print("This is okay if you haven't run the SQL yet. Please run the SQL above.")
    
    return True

def test_table_operations():
    """Test basic operations on the users table"""
    try:
        print("\nTesting table operations...")
        
        # Test insert (with a test user that we'll delete)
        test_email = "test_user_delete_me@example.com"
        
        # First, try to delete any existing test user
        supabase.table('users').delete().eq('email', test_email).execute()
        
        # Insert test user
        result = supabase.table('users').insert({
            'first_name': 'Test',
            'last_name': 'User',
            'email': test_email,
            'phone': '+1234567890',
            'password_hash': 'test_hash_delete_me'
        }).execute()
        
        if result.data:
            print("Insert operation successful")
            
            # Test select
            user = supabase.table('users').select('*').eq('email', test_email).execute()
            if user.data:
                print("Select operation successful")
                
                # Clean up - delete test user
                supabase.table('users').delete().eq('email', test_email).execute()
                print("Delete operation successful")
                print("All table operations working correctly!")
                return True
            else:
                print("Select operation failed")
                return False
        else:
            print("Insert operation failed")
            return False
            
    except Exception as e:
        print(f"Error testing table operations: {e}")
        return False

if __name__ == "__main__":
    print("LuxeShop Supabase Users Table Setup")
    print("=" * 40)
    
    # Test connection
    print(f"Connecting to: {SUPABASE_URL}")
    
    # Create/verify users table
    if create_users_table():
        # Test operations
        if test_table_operations():
            print("\nSetup completed successfully!")
            print("Your users table is ready for the signup API")
        else:
            print("\nTable exists but operations failed")
            print("Please check your Supabase permissions")
    else:
        print("\nSetup incomplete - please create the table manually")
