import requests
import unittest
import json
import sys
from datetime import datetime

class ExpenseTrackerAPITest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ExpenseTrackerAPITest, self).__init__(*args, **kwargs)
        self.base_url = "http://localhost:8001/api"
        self.token = None
        self.user_id = None
        self.test_email = "test@example.com"
        self.test_username = "testuser"
        self.test_password = "Password123!"
        self.test_category_id = None
        self.test_expense_id = None

    def setUp(self):
        # Clean up any existing test user
        self._cleanup_test_user()

    def _cleanup_test_user(self):
        """Try to clean up the test user if it exists"""
        try:
            # Try to login with test credentials
            login_data = {
                "username": self.test_email,
                "password": self.test_password
            }
            response = requests.post(f"{self.base_url}/token", data=login_data)
            if response.status_code == 200:
                # If login successful, we need to clean up
                token_data = response.json()
                self.token = token_data["access_token"]
                
                # Get user expenses and delete them
                headers = {"Authorization": f"Bearer {self.token}"}
                expenses_response = requests.get(f"{self.base_url}/expenses", headers=headers)
                if expenses_response.status_code == 200:
                    expenses = expenses_response.json()
                    for expense in expenses:
                        requests.delete(f"{self.base_url}/expenses/{expense['id']}", headers=headers)
                
                # Get user categories and delete them
                categories_response = requests.get(f"{self.base_url}/categories", headers=headers)
                if categories_response.status_code == 200:
                    categories = categories_response.json()
                    for category in categories:
                        if category.get("user_id"):  # Only delete user's custom categories
                            requests.delete(f"{self.base_url}/categories/{category['id']}", headers=headers)
        except:
            # If any error occurs during cleanup, just continue
            pass

    def test_01_register(self):
        """Test user registration"""
        print("\n🔍 Testing user registration...")
        
        register_data = {
            "email": self.test_email,
            "username": self.test_username,
            "password": self.test_password
        }
        
        response = requests.post(f"{self.base_url}/register", json=register_data)
        self.assertEqual(response.status_code, 200, f"Registration failed: {response.text}")
        
        user_data = response.json()
        self.assertIn("id", user_data, "User ID not found in response")
        self.assertEqual(user_data["email"], self.test_email, "Email in response doesn't match")
        self.assertEqual(user_data["username"], self.test_username, "Username in response doesn't match")
        
        self.user_id = user_data["id"]
        print("✅ User registration successful")

    def test_02_login(self):
        """Test user login"""
        print("\n🔍 Testing user login...")
        
        login_data = {
            "username": self.test_email,
            "password": self.test_password
        }
        
        response = requests.post(f"{self.base_url}/token", data=login_data)
        self.assertEqual(response.status_code, 200, f"Login failed: {response.text}")
        
        token_data = response.json()
        self.assertIn("access_token", token_data, "Token not found in response")
        self.assertIn("token_type", token_data, "Token type not found in response")
        
        self.token = token_data["access_token"]
        print("✅ User login successful")

    def test_03_get_user_profile(self):
        """Test getting user profile"""
        print("\n🔍 Testing get user profile...")
        
        if not self.token:
            self.test_02_login()
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/me", headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Get profile failed: {response.text}")
        
        user_data = response.json()
        self.assertEqual(user_data["email"], self.test_email, "Email in profile doesn't match")
        self.assertEqual(user_data["username"], self.test_username, "Username in profile doesn't match")
        
        print("✅ Get user profile successful")

    def test_04_get_categories(self):
        """Test getting categories"""
        print("\n🔍 Testing get categories...")
        
        if not self.token:
            self.test_02_login()
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/categories", headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Get categories failed: {response.text}")
        
        categories = response.json()
        self.assertTrue(len(categories) > 0, "No categories returned")
        
        # Check if preset categories exist
        preset_categories = ["Groceries", "Entertainment", "Restaurants", "Uber/Lyft", 
                            "Auto", "Insurance", "Housing", "Utilities", "Healthcare", "Education"]
        
        found_categories = [category["name"] for category in categories]
        for preset in preset_categories:
            self.assertIn(preset, found_categories, f"Preset category '{preset}' not found")
        
        print("✅ Get categories successful")

    def test_05_create_category(self):
        """Test creating a custom category"""
        print("\n🔍 Testing create custom category...")
        
        if not self.token:
            self.test_02_login()
        
        category_name = "Entertainment"
        category_data = {"name": category_name}
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(f"{self.base_url}/categories", json=category_data, headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Create category failed: {response.text}")
        
        category = response.json()
        self.assertEqual(category["name"], category_name, "Category name doesn't match")
        self.assertIsNotNone(category["id"], "Category ID not found")
        
        self.test_category_id = category["id"]
        print("✅ Create custom category successful")

    def test_06_create_expense(self):
        """Test creating an expense"""
        print("\n🔍 Testing create expense...")
        
        if not self.token:
            self.test_02_login()
        
        if not self.test_category_id:
            # Get a category ID if we don't have one
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.base_url}/categories", headers=headers)
            categories = response.json()
            self.test_category_id = categories[0]["id"]
        
        expense_data = {
            "amount": 25.50,
            "description": "Groceries",
            "category_id": self.test_category_id,
            "date": datetime.now().isoformat()
        }
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(f"{self.base_url}/expenses", json=expense_data, headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Create expense failed: {response.text}")
        
        expense = response.json()
        self.assertEqual(float(expense["amount"]), expense_data["amount"], "Expense amount doesn't match")
        self.assertEqual(expense["description"], expense_data["description"], "Expense description doesn't match")
        self.assertEqual(expense["category_id"], expense_data["category_id"], "Expense category doesn't match")
        
        self.test_expense_id = expense["id"]
        print("✅ Create expense successful")

    def test_07_get_expenses(self):
        """Test getting expenses"""
        print("\n🔍 Testing get expenses...")
        
        if not self.token:
            self.test_02_login()
        
        if not self.test_expense_id:
            self.test_06_create_expense()
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/expenses", headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Get expenses failed: {response.text}")
        
        expenses = response.json()
        self.assertTrue(len(expenses) > 0, "No expenses returned")
        
        # Check if our test expense is in the list
        expense_ids = [expense["id"] for expense in expenses]
        self.assertIn(self.test_expense_id, expense_ids, "Test expense not found in expenses list")
        
        print("✅ Get expenses successful")

    def test_08_update_expense(self):
        """Test updating an expense"""
        print("\n🔍 Testing update expense...")
        
        if not self.token:
            self.test_02_login()
        
        if not self.test_expense_id:
            self.test_06_create_expense()
        
        updated_expense_data = {
            "amount": 30.00,
            "description": "Updated Groceries",
            "category_id": self.test_category_id,
            "date": datetime.now().isoformat()
        }
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.put(
            f"{self.base_url}/expenses/{self.test_expense_id}", 
            json=updated_expense_data, 
            headers=headers
        )
        
        self.assertEqual(response.status_code, 200, f"Update expense failed: {response.text}")
        
        expense = response.json()
        self.assertEqual(float(expense["amount"]), updated_expense_data["amount"], "Updated expense amount doesn't match")
        self.assertEqual(expense["description"], updated_expense_data["description"], "Updated expense description doesn't match")
        
        print("✅ Update expense successful")

    def test_09_delete_expense(self):
        """Test deleting an expense"""
        print("\n🔍 Testing delete expense...")
        
        if not self.token:
            self.test_02_login()
        
        if not self.test_expense_id:
            self.test_06_create_expense()
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.delete(f"{self.base_url}/expenses/{self.test_expense_id}", headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Delete expense failed: {response.text}")
        
        # Verify expense is deleted
        get_response = requests.get(f"{self.base_url}/expenses", headers=headers)
        expenses = get_response.json()
        expense_ids = [expense["id"] for expense in expenses]
        self.assertNotIn(self.test_expense_id, expense_ids, "Expense still exists after deletion")
        
        print("✅ Delete expense successful")

    def test_10_theme_settings(self):
        """Test theme settings"""
        print("\n🔍 Testing theme settings...")
        
        if not self.token:
            self.test_02_login()
        
        # Get current theme
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/theme", headers=headers)
        
        self.assertEqual(response.status_code, 200, f"Get theme failed: {response.text}")
        
        # Update theme
        theme_data = {
            "color_theme": "purple",
            "mode": "dark"
        }
        
        update_response = requests.put(f"{self.base_url}/theme", json=theme_data, headers=headers)
        
        self.assertEqual(update_response.status_code, 200, f"Update theme failed: {update_response.text}")
        
        updated_theme = update_response.json()
        self.assertEqual(updated_theme["color_theme"], theme_data["color_theme"], "Theme color doesn't match")
        self.assertEqual(updated_theme["mode"], theme_data["mode"], "Theme mode doesn't match")
        
        print("✅ Theme settings test successful")

    def test_11_reports(self):
        """Test reports functionality"""
        print("\n🔍 Testing reports functionality...")
        
        if not self.token:
            self.test_02_login()
        
        # Create some expenses for reports
        if not self.test_category_id:
            # Get a category ID if we don't have one
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.base_url}/categories", headers=headers)
            categories = response.json()
            self.test_category_id = categories[0]["id"]
        
        # Create multiple expenses
        headers = {"Authorization": f"Bearer {self.token}"}
        for i, amount in enumerate([15.75, 42.99, 8.50, 22.25]):
            expense_data = {
                "amount": amount,
                "description": f"Test Expense {i+1}",
                "category_id": self.test_category_id,
                "date": datetime.now().isoformat()
            }
            requests.post(f"{self.base_url}/expenses", json=expense_data, headers=headers)
        
        # Test summary report
        summary_response = requests.get(f"{self.base_url}/reports/summary", headers=headers)
        self.assertEqual(summary_response.status_code, 200, f"Get summary report failed: {summary_response.text}")
        
        summary = summary_response.json()
        self.assertIn("total_expenses", summary, "Total expenses not found in summary")
        self.assertIn("categories", summary, "Categories not found in summary")
        
        # Test trends report
        trends_response = requests.get(f"{self.base_url}/reports/trends", headers=headers)
        self.assertEqual(trends_response.status_code, 200, f"Get trends report failed: {trends_response.text}")
        
        # Test charts report
        charts_response = requests.get(f"{self.base_url}/reports/charts", headers=headers)
        self.assertEqual(charts_response.status_code, 200, f"Get charts report failed: {charts_response.text}")
        
        print("✅ Reports functionality test successful")

def run_tests():
    # Create a test suite
    test_suite = unittest.TestSuite()
    
    # Add tests in order
    test_suite.addTest(ExpenseTrackerAPITest('test_01_register'))
    test_suite.addTest(ExpenseTrackerAPITest('test_02_login'))
    test_suite.addTest(ExpenseTrackerAPITest('test_03_get_user_profile'))
    test_suite.addTest(ExpenseTrackerAPITest('test_04_get_categories'))
    test_suite.addTest(ExpenseTrackerAPITest('test_05_create_category'))
    test_suite.addTest(ExpenseTrackerAPITest('test_06_create_expense'))
    test_suite.addTest(ExpenseTrackerAPITest('test_07_get_expenses'))
    test_suite.addTest(ExpenseTrackerAPITest('test_08_update_expense'))
    test_suite.addTest(ExpenseTrackerAPITest('test_09_delete_expense'))
    test_suite.addTest(ExpenseTrackerAPITest('test_10_theme_settings'))
    test_suite.addTest(ExpenseTrackerAPITest('test_11_reports'))
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    print("\n📊 EXPENSE TRACKER API TEST SUITE")
    print("=" * 40)
    sys.exit(run_tests())