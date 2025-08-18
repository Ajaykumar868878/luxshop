import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_table_schema(table_name):
    try:
        # This is a way to get schema-like information. 
        # Supabase-py doesn't have a direct schema fetch method, 
        # so we fetch one row and get its keys.
        response = supabase.table(table_name).select('*').limit(1).execute()
        if response.data:
            print(f"Schema for '{table_name}': {list(response.data[0].keys())}")
        else:
            print(f"Could not retrieve schema for '{table_name}'. The table might be empty or inaccessible.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    get_table_schema('users')
