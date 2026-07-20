# test_db.py
import sys
import traceback

print("=" * 50)
print("🚀 TEST SCRIPT STARTED")
print("=" * 50)

try:
    from backend.db_connector import DatabaseHandler
    print("✅ db_connector imported successfully")
except Exception as e:
    print("❌ Import failed:")
    traceback.print_exc()
    sys.exit(1)

# Create DB instance
db = DatabaseHandler()
print("✅ DatabaseHandler instance created")

# Connect
print("Connecting to database...")
if db.connect():
    print("✅ Database connected")
else:
    print("❌ Database connection failed")
    sys.exit(1)

# Test create_user
print("\n--- Testing create_user ---")
try:
    result = db.create_user("testuser3", "test4@example.com", "mypassword123")
    print(f"✅ Result: {result}")
except Exception as e:
    print("❌ Exception during create_user:")
    traceback.print_exc()

db.close()
print("\n✅ Test complete")