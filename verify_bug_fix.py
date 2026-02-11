"""
Verification script to confirm UnboundLocalError bug fixes in database.py and inventory.py
"""

import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sentinel.database import Database, DatabaseError
from sentinel.inventory import ResourceInventory, InventoryError


def test_database_connection_failure():
    """Test that database.py handles connection failures gracefully without UnboundLocalError."""
    print("Testing database.py connection failure handling...")

    # Test 1: Non-existent path with read_only=True (most likely to trigger the bug)
    try:
        db = Database(Path("/nonexistent/path/database.db"), read_only=True)
        with db.get_connection() as conn:
            pass
        print("  ERROR: Expected DatabaseError but connection succeeded")
        return False
    except DatabaseError as e:
        print(f"  PASS: DatabaseError raised correctly: {e}")
    except UnboundLocalError as e:
        print(f"  FAIL: UnboundLocalError still occurs: {e}")
        return False
    except Exception as e:
        print(f"  FAIL: Unexpected exception: {type(e).__name__}: {e}")
        return False

    # Test 2: Invalid URI path
    try:
        db = Database(Path("/invalid/\x00/path.db"), read_only=False)
        with db.get_connection() as conn:
            pass
        print("  WARNING: Connection succeeded on invalid path (may be OS-dependent)")
    except DatabaseError as e:
        print(f"  PASS: DatabaseError raised correctly for invalid path: {e}")
    except UnboundLocalError as e:
        print(f"  FAIL: UnboundLocalError still occurs: {e}")
        return False
    except Exception as e:
        # Some OSes may raise different exceptions
        print(f"  INFO: Other exception raised: {type(e).__name__}: {e}")

    return True


def test_inventory_connection_failure():
    """Test that inventory.py handles connection failures gracefully without UnboundLocalError."""
    print("\nTesting inventory.py connection failure handling...")

    # Test 1: Non-existent path with read_only=True
    try:
        inv = ResourceInventory(Path("/nonexistent/path/inventory.db"), read_only=True)
        with inv.get_connection() as conn:
            pass
        print("  ERROR: Expected InventoryError but connection succeeded")
        return False
    except InventoryError as e:
        print(f"  PASS: InventoryError raised correctly: {e}")
    except UnboundLocalError as e:
        print(f"  FAIL: UnboundLocalError still occurs: {e}")
        return False
    except Exception as e:
        print(f"  FAIL: Unexpected exception: {type(e).__name__}: {e}")
        return False

    # Test 2: Invalid URI path
    try:
        inv = ResourceInventory(Path("/invalid/\x00/path.db"), read_only=False)
        with inv.get_connection() as conn:
            pass
        print("  WARNING: Connection succeeded on invalid path (may be OS-dependent)")
    except InventoryError as e:
        print(f"  PASS: InventoryError raised correctly for invalid path: {e}")
    except UnboundLocalError as e:
        print(f"  FAIL: UnboundLocalError still occurs: {e}")
        return False
    except Exception as e:
        # Some OSes may raise different exceptions
        print(f"  INFO: Other exception raised: {type(e).__name__}: {e}")

    return True


def test_successful_connection():
    """Test that successful connections still work correctly after the fix."""
    print("\nTesting successful connection handling...")

    # Test database.py with temporary file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        db = Database(tmp_path)
        db.create_schema()

        with db.get_connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        if len(tables) > 0:
            print(f"  PASS: database.py successful connection works (found {len(tables)} tables)")
        else:
            print("  FAIL: database.py connection succeeded but no tables found")
            return False
    except Exception as e:
        print(f"  FAIL: database.py successful connection failed: {e}")
        return False
    finally:
        tmp_path.unlink(missing_ok=True)

    # Test inventory.py with temporary file
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        inv = ResourceInventory(tmp_path)
        inv.create_schema()

        with inv.get_connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        if len(tables) > 0:
            print(f"  PASS: inventory.py successful connection works (found {len(tables)} tables)")
        else:
            print("  FAIL: inventory.py connection succeeded but no tables found")
            return False
    except Exception as e:
        print(f"  FAIL: inventory.py successful connection failed: {e}")
        return False
    finally:
        tmp_path.unlink(missing_ok=True)

    return True


def main():
    print("=" * 70)
    print("Bug Fix Verification: UnboundLocalError in Exception Handling")
    print("=" * 70)
    print()

    results = []

    # Run all tests
    results.append(("Database Connection Failure", test_database_connection_failure()))
    results.append(("Inventory Connection Failure", test_inventory_connection_failure()))
    results.append(("Successful Connection", test_successful_connection()))

    # Print summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)

    for test_name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {status}: {test_name}")

    all_passed = all(passed for _, passed in results)

    print()
    if all_passed:
        print("RESULT: ALL VERIFICATIONS PASSED")
        print("The UnboundLocalError bug has been successfully fixed in both modules.")
        return 0
    else:
        print("RESULT: SOME VERIFICATIONS FAILED")
        print("Please review the failed tests above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
