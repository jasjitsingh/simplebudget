import React, { useState, useEffect, createContext, useContext } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Auth Context
const AuthContext = createContext();

function useAuth() {
  return useContext(AuthContext);
}

function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const navigate = useNavigate();

  useEffect(() => {
    if (token) {
      fetchUserProfile();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUserProfile = async () => {
    try {
      const response = await axios.get(`${process.env.REACT_APP_BACKEND_URL}/api/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setCurrentUser(response.data);
    } catch (error) {
      console.error('Error fetching user profile:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${process.env.REACT_APP_BACKEND_URL}/api/token`, 
        new URLSearchParams({
          'username': email,
          'password': password,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
      const { access_token } = response.data;
      localStorage.setItem('token', access_token);
      setToken(access_token);
      return true;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  };

  const register = async (username, email, password) => {
    try {
      await axios.post(`${process.env.REACT_APP_BACKEND_URL}/api/register`, {
        username,
        email,
        password
      });
      return true;
    } catch (error) {
      console.error('Registration error:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setCurrentUser(null);
    navigate('/login');
  };

  const value = {
    currentUser,
    token,
    login,
    register,
    logout,
    fetchUserProfile
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}

// Theme Context
const ThemeContext = createContext();

function useTheme() {
  return useContext(ThemeContext);
}

function ThemeProvider({ children }) {
  const [colorTheme, setColorTheme] = useState('blue');
  const [mode, setMode] = useState('light');
  const { token } = useAuth();

  useEffect(() => {
    if (token) {
      fetchThemeSettings();
    } else {
      // Default theme settings
      applyTheme('blue', 'light');
    }
  }, [token]);

  const fetchThemeSettings = async () => {
    try {
      const response = await axios.get(`${process.env.REACT_APP_BACKEND_URL}/api/theme`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const { color_theme, mode } = response.data;
      setColorTheme(color_theme);
      setMode(mode);
      applyTheme(color_theme, mode);
    } catch (error) {
      console.error('Error fetching theme settings:', error);
      // Use default theme
      applyTheme('blue', 'light');
    }
  };

  const updateTheme = async (newColorTheme, newMode) => {
    try {
      await axios.put(
        `${process.env.REACT_APP_BACKEND_URL}/api/theme`,
        {
          color_theme: newColorTheme,
          mode: newMode
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      
      setColorTheme(newColorTheme);
      setMode(newMode);
      applyTheme(newColorTheme, newMode);
    } catch (error) {
      console.error('Error updating theme:', error);
    }
  };

  const applyTheme = (color, displayMode) => {
    document.body.className = `theme-${displayMode} theme-${color}`;
  };

  const value = {
    colorTheme,
    mode,
    updateTheme
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// Components
function PrivateRoute({ children }) {
  const { currentUser } = useAuth();
  
  return currentUser ? children : <Navigate to="/login" />;
}

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    if (!email || !password) {
      setError('Please enter both email and password');
      setIsLoading(false);
      return;
    }
    
    const success = await login(email, password);
    setIsLoading(false);
    
    if (success) {
      navigate('/dashboard');
    } else {
      setError('Failed to log in. Please check your credentials.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="max-w-md w-full space-y-8 p-8 bg-white dark:bg-gray-800 rounded-lg shadow-md">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
            Sign in to your account
          </h2>
        </div>
        
        {error && (
          <div className="p-3 bg-red-50 text-red-500 rounded-md text-sm">
            {error}
          </div>
        )}
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="email-address" className="sr-only">Email address</label>
              <input
                id="email-address"
                name="email"
                type="email"
                autoComplete="email"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 rounded-t-md focus:outline-none focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 focus:z-10 sm:text-sm"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">Password</label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 rounded-b-md focus:outline-none focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className={`group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isLoading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>
          
          <div className="text-center text-sm">
            <p className="text-gray-600 dark:text-gray-300">
              Don't have an account?{' '}
              <a href="/register" className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400">
                Register
              </a>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}

function RegisterPage() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { register, login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    // Basic validation
    if (!username || !email || !password) {
      setError('Please fill in all fields');
      setIsLoading(false);
      return;
    }
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setIsLoading(false);
      return;
    }
    
    const success = await register(username, email, password);
    
    if (success) {
      // Auto-login after registration
      const loginSuccess = await login(email, password);
      setIsLoading(false);
      
      if (loginSuccess) {
        navigate('/dashboard');
      } else {
        navigate('/login');
      }
    } else {
      setIsLoading(false);
      setError('Failed to register. Email may already be in use.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="max-w-md w-full space-y-8 p-8 bg-white dark:bg-gray-800 rounded-lg shadow-md">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
            Create a new account
          </h2>
        </div>
        
        {error && (
          <div className="p-3 bg-red-50 text-red-500 rounded-md text-sm">
            {error}
          </div>
        )}
        
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">Username</label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 rounded-t-md focus:outline-none focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 focus:z-10 sm:text-sm"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="email-address" className="sr-only">Email address</label>
              <input
                id="email-address"
                name="email"
                type="email"
                autoComplete="email"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 dark:bg-gray-700 focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10 sm:text-sm"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">Password</label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 dark:bg-gray-700 focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="confirm-password" className="sr-only">Confirm Password</label>
              <input
                id="confirm-password"
                name="confirm-password"
                type="password"
                autoComplete="new-password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-700 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 dark:bg-gray-700 rounded-b-md focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10 sm:text-sm"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className={`group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isLoading ? 'Creating account...' : 'Sign up'}
            </button>
          </div>
          
          <div className="text-center text-sm">
            <p className="text-gray-600 dark:text-gray-300">
              Already have an account?{' '}
              <a href="/login" className="font-medium text-primary-600 hover:text-primary-500 dark:text-primary-400">
                Sign in
              </a>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}

function Dashboard() {
  const { currentUser, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('expenses');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  
  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      {/* Header */}
      <nav className="bg-white dark:bg-gray-800 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <h1 className="text-xl font-bold text-primary-600">ExpenseTracker</h1>
              </div>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:items-center sm:space-x-8">
              <button
                type="button"
                className={`px-3 py-2 rounded-md text-sm font-medium ${activeTab === 'expenses' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'}`}
                onClick={() => setActiveTab('expenses')}
              >
                Expenses
              </button>
              <button
                type="button"
                className={`px-3 py-2 rounded-md text-sm font-medium ${activeTab === 'reports' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'}`}
                onClick={() => setActiveTab('reports')}
              >
                Reports
              </button>
              <button
                type="button"
                className={`px-3 py-2 rounded-md text-sm font-medium ${activeTab === 'settings' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'}`}
                onClick={() => setActiveTab('settings')}
              >
                Settings
              </button>
              <div className="ml-3 relative">
                <div>
                  <span className="text-gray-700 dark:text-gray-300">{currentUser?.username}</span>
                  <button
                    onClick={logout}
                    className="ml-4 px-3 py-1 text-sm text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    Logout
                  </button>
                </div>
              </div>
            </div>
            <div className="-mr-2 flex items-center sm:hidden">
              <button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="bg-white dark:bg-gray-800 inline-flex items-center justify-center p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500"
              >
                <span className="sr-only">Open main menu</span>
                <svg className="block h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        <div className={`${isMobileMenuOpen ? 'block' : 'hidden'} sm:hidden`}>
          <div className="pt-2 pb-3 space-y-1">
            <button
              onClick={() => { setActiveTab('expenses'); setIsMobileMenuOpen(false); }}
              className={`block px-3 py-2 rounded-md text-base font-medium ${activeTab === 'expenses' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'} w-full text-left`}
            >
              Expenses
            </button>
            <button
              onClick={() => { setActiveTab('reports'); setIsMobileMenuOpen(false); }}
              className={`block px-3 py-2 rounded-md text-base font-medium ${activeTab === 'reports' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'} w-full text-left`}
            >
              Reports
            </button>
            <button
              onClick={() => { setActiveTab('settings'); setIsMobileMenuOpen(false); }}
              className={`block px-3 py-2 rounded-md text-base font-medium ${activeTab === 'settings' ? 'bg-primary-100 dark:bg-primary-900 text-primary-800 dark:text-primary-200' : 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white'} w-full text-left`}
            >
              Settings
            </button>
          </div>
          <div className="pt-4 pb-3 border-t border-gray-200 dark:border-gray-700">
            <div className="flex items-center px-4">
              <div className="ml-3">
                <div className="text-base font-medium text-gray-800 dark:text-white">{currentUser?.username}</div>
                <div className="text-sm font-medium text-gray-500 dark:text-gray-400">{currentUser?.email}</div>
              </div>
            </div>
            <div className="mt-3 space-y-1">
              <button
                onClick={logout}
                className="block w-full text-left px-4 py-2 text-base font-medium text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {activeTab === 'expenses' && <ExpensesTab />}
        {activeTab === 'reports' && <ReportsTab />}
        {activeTab === 'settings' && <SettingsTab />}
      </main>
    </div>
  );
}

function ExpensesTab() {
  const { token } = useAuth();
  const [expenses, setExpenses] = useState([]);
  const [categories, setCategories] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddExpense, setShowAddExpense] = useState(false);
  const [showAddCategory, setShowAddCategory] = useState(false);
  const [currentExpense, setCurrentExpense] = useState(null);

  // Form states
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [date, setDate] = useState(new Date().toISOString().split('T')[0]);
  const [error, setError] = useState('');
  const [newCategoryName, setNewCategoryName] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      try {
        // Fetch categories
        const categoriesResponse = await axios.get(
          `${process.env.REACT_APP_BACKEND_URL}/api/categories`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        setCategories(categoriesResponse.data);
        
        // Set default category
        if (categoriesResponse.data.length > 0 && !categoryId) {
          setCategoryId(categoriesResponse.data[0].id);
        }
        
        // Fetch expenses
        const expensesResponse = await axios.get(
          `${process.env.REACT_APP_BACKEND_URL}/api/expenses`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        setExpenses(expensesResponse.data);
      } catch (error) {
        console.error('Error fetching expenses/categories:', error);
        setError('Failed to load expenses or categories');
      } finally {
        setIsLoading(false);
      }
    };
    
    fetchData();
  }, [token]);

  const handleAddExpense = async (e) => {
    e.preventDefault();
    
    try {
      const expenseData = {
        amount: parseFloat(amount),
        description,
        category_id: categoryId,
        date: new Date(date).toISOString()
      };
      
      if (currentExpense) {
        // Update existing expense
        await axios.put(
          `${process.env.REACT_APP_BACKEND_URL}/api/expenses/${currentExpense.id}`,
          expenseData,
          { headers: { Authorization: `Bearer ${token}` } }
        );
      } else {
        // Add new expense
        await axios.post(
          `${process.env.REACT_APP_BACKEND_URL}/api/expenses`,
          expenseData,
          { headers: { Authorization: `Bearer ${token}` } }
        );
      }
      
      // Refresh expenses list
      const response = await axios.get(
        `${process.env.REACT_APP_BACKEND_URL}/api/expenses`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setExpenses(response.data);
      
      // Reset form
      setAmount('');
      setDescription('');
      setCategoryId(categories[0]?.id || '');
      setDate(new Date().toISOString().split('T')[0]);
      setCurrentExpense(null);
      setShowAddExpense(false);
      setError('');
    } catch (error) {
      console.error('Error adding/updating expense:', error);
      setError('Failed to save expense. Please check your inputs.');
    }
  };

  const handleAddCategory = async (e) => {
    e.preventDefault();
    
    if (!newCategoryName.trim()) {
      setError('Category name cannot be empty');
      return;
    }
    
    try {
      // Add new category
      await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/api/categories`,
        { name: newCategoryName },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      // Refresh categories list
      const response = await axios.get(
        `${process.env.REACT_APP_BACKEND_URL}/api/categories`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setCategories(response.data);
      
      // Reset form
      setNewCategoryName('');
      setShowAddCategory(false);
      setError('');
    } catch (error) {
      console.error('Error adding category:', error);
      setError('Failed to add category. It might already exist.');
    }
  };

  const handleDeleteExpense = async (id) => {
    if (!window.confirm('Are you sure you want to delete this expense?')) {
      return;
    }
    
    try {
      await axios.delete(
        `${process.env.REACT_APP_BACKEND_URL}/api/expenses/${id}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      // Update expenses list
      setExpenses(expenses.filter(expense => expense.id !== id));
    } catch (error) {
      console.error('Error deleting expense:', error);
      setError('Failed to delete expense');
    }
  };

  const handleEditExpense = (expense) => {
    setCurrentExpense(expense);
    setAmount(expense.amount.toString());
    setDescription(expense.description);
    setCategoryId(expense.category_id);
    setDate(expense.date.split('T')[0]);
    setShowAddExpense(true);
  };

  if (isLoading) {
    return <div className="text-center py-10">Loading expenses...</div>;
  }

  return (
    <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
      <div className="px-4 py-5 sm:px-6 flex justify-between items-center">
        <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
          My Expenses
        </h3>
        <div className="space-x-2">
          <button
            onClick={() => setShowAddCategory(true)}
            className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md text-gray-700 dark:text-gray-200 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            Add Category
          </button>
          <button
            onClick={() => {
              setCurrentExpense(null);
              setAmount('');
              setDescription('');
              setCategoryId(categories[0]?.id || '');
              setDate(new Date().toISOString().split('T')[0]);
              setShowAddExpense(true);
            }}
            className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            Add Expense
          </button>
        </div>
      </div>
      
      {error && (
        <div className="mx-4 mb-4 p-3 bg-red-50 text-red-500 rounded-md text-sm">
          {error}
        </div>
      )}
      
      {/* Add Category Modal */}
      {showAddCategory && (
        <div className="fixed inset-0 overflow-y-auto z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md mx-auto p-6 shadow-xl">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Add New Category
            </h3>
            <form onSubmit={handleAddCategory}>
              <div className="mb-4">
                <label htmlFor="category-name" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Category Name
                </label>
                <input
                  type="text"
                  id="category-name"
                  className="mt-1 block w-full border-gray-300 dark:border-gray-700 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white sm:text-sm"
                  value={newCategoryName}
                  onChange={(e) => setNewCategoryName(e.target.value)}
                  placeholder="Enter category name"
                  required
                />
              </div>
              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowAddCategory(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                >
                  Add Category
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      {/* Add/Edit Expense Modal */}
      {showAddExpense && (
        <div className="fixed inset-0 overflow-y-auto z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md mx-auto p-6 shadow-xl">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              {currentExpense ? 'Edit Expense' : 'Add New Expense'}
            </h3>
            <form onSubmit={handleAddExpense}>
              <div className="mb-4">
                <label htmlFor="amount" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Amount
                </label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <span className="text-gray-500 dark:text-gray-400 sm:text-sm">$</span>
                  </div>
                  <input
                    type="number"
                    id="amount"
                    min="0"
                    step="0.01"
                    className="mt-1 block w-full pl-8 border-gray-300 dark:border-gray-700 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white sm:text-sm"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    placeholder="0.00"
                    required
                  />
                </div>
              </div>
              <div className="mb-4">
                <label htmlFor="description" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Description
                </label>
                <input
                  type="text"
                  id="description"
                  className="mt-1 block w-full border-gray-300 dark:border-gray-700 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white sm:text-sm"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What was this expense for?"
                  required
                />
              </div>
              <div className="mb-4">
                <label htmlFor="category" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Category
                </label>
                <select
                  id="category"
                  className="mt-1 block w-full border-gray-300 dark:border-gray-700 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white sm:text-sm"
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  required
                >
                  {categories.map((category) => (
                    <option key={category.id} value={category.id}>
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="mb-4">
                <label htmlFor="date" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Date
                </label>
                <input
                  type="date"
                  id="date"
                  className="mt-1 block w-full border-gray-300 dark:border-gray-700 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-white sm:text-sm"
                  value={date}
                  onChange={(e) => setDate(e.target.value)}
                  required
                />
              </div>
              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowAddExpense(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                >
                  {currentExpense ? 'Update Expense' : 'Add Expense'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      {/* Expenses List */}
      <div className="overflow-x-auto">
        {expenses.length === 0 ? (
          <div className="text-center py-10 text-gray-500 dark:text-gray-400">
            No expenses found. Add your first expense to get started!
          </div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Date
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Category
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Description
                </th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Amount
                </th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {expenses.map((expense) => (
                <tr key={expense.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                    {new Date(expense.date).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                    {expense.category_name}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-300">
                    {expense.description}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-500 dark:text-gray-300">
                    ${expense.amount.toFixed(2)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleEditExpense(expense)}
                      className="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300 mr-3"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDeleteExpense(expense.id)}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ReportsTab() {
  const { token } = useAuth();
  const [activeReportType, setActiveReportType] = useState('summary');
  const [period, setPeriod] = useState('month');
  const [dateRange, setDateRange] = useState({
    startDate: new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0],
    endDate: new Date().toISOString().split('T')[0]
  });
  const [chartType, setChartType] = useState('pie');
  const [reportData, setReportData] = useState(null);
  const [trendData, setTrendData] = useState(null);
  const [chartData, setChartData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchReport();
  }, [activeReportType, period, dateRange, chartType, token]);

  const fetchReport = async () => {
    setIsLoading(true);
    setError('');
    
    try {
      let response;
      
      if (activeReportType === 'summary') {
        response = await axios.get(
          `${process.env.REACT_APP_BACKEND_URL}/api/reports/summary`,
          {
            params: {
              period,
              start_date: dateRange.startDate,
              end_date: dateRange.endDate
            },
            headers: { Authorization: `Bearer ${token}` }
          }
        );
        setReportData(response.data);
      } else if (activeReportType === 'trends') {
        response = await axios.get(
          `${process.env.REACT_APP_BACKEND_URL}/api/reports/trends`,
          {
            params: {
              period,
              months: 12 // Default to 12 months analysis
            },
            headers: { Authorization: `Bearer ${token}` }
          }
        );
        setTrendData(response.data);
      } else if (activeReportType === 'charts') {
        response = await axios.get(
          `${process.env.REACT_APP_BACKEND_URL}/api/reports/charts`,
          {
            params: {
              chart_type: chartType,
              period,
              start_date: dateRange.startDate,
              end_date: dateRange.endDate
            },
            headers: { Authorization: `Bearer ${token}` }
          }
        );
        setChartData(response.data);
      }
    } catch (error) {
      console.error(`Error fetching ${activeReportType} report:`, error);
      setError(`Failed to load the ${activeReportType} report. Please try again.`);
    } finally {
      setIsLoading(false);
    }
  };

  const exportPDF = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(
        `${process.env.REACT_APP_BACKEND_URL}/api/reports/export-pdf`,
        {
          params: {
            period,
            start_date: dateRange.startDate,
            end_date: dateRange.endDate
          },
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      
      // Create and download PDF
      const { pdf_data, filename } = response.data;
      const link = document.createElement('a');
      link.href = `data:application/pdf;base64,${pdf_data}`;
      link.download = filename;
      link.click();
    } catch (error) {
      console.error('Error exporting PDF:', error);
      setError('Failed to export PDF report. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
      <div className="px-4 py-5 sm:px-6">
        <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
          Expense Reports
        </h3>
      </div>
      
      {error && (
        <div className="mx-4 mb-4 p-3 bg-red-50 text-red-500 rounded-md text-sm">
          {error}
        </div>
      )}
      
      <div className="border-t border-gray-200 dark:border-gray-700 p-4">
        {/* Report Type Tabs */}
        <div className="flex flex-wrap gap-2 border-b border-gray-200 dark:border-gray-700 mb-4">
          <button
            onClick={() => setActiveReportType('summary')}
            className={`py-2 px-4 text-sm font-medium rounded-t-md focus:outline-none ${
              activeReportType === 'summary'
                ? 'border-b-2 border-primary-500 text-primary-600 dark:text-primary-400'
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
            }`}
          >
            Summary
          </button>
          <button
            onClick={() => setActiveReportType('trends')}
            className={`py-2 px-4 text-sm font-medium rounded-t-md focus:outline-none ${
              activeReportType === 'trends'
                ? 'border-b-2 border-primary-500 text-primary-600 dark:text-primary-400'
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
            }`}
          >
            Trends
          </button>
          <button
            onClick={() => setActiveReportType('charts')}
            className={`py-2 px-4 text-sm font-medium rounded-t-md focus:outline-none ${
              activeReportType === 'charts'
                ? 'border-b-2 border-primary-500 text-primary-600 dark:text-primary-400'
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
            }`}
          >
            Charts
          </button>
        </div>
        
        {/* Report Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Period
            </label>
            <select
              value={period}
              onChange={(e) => setPeriod(e.target.value)}
              className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-700 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md"
            >
              <option value="day">Day</option>
              <option value="week">Week</option>
              <option value="month">Month</option>
              <option value="year">Year</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Start Date
            </label>
            <input
              type="date"
              value={dateRange.startDate}
              onChange={(e) => setDateRange({...dateRange, startDate: e.target.value})}
              className="mt-1 block w-full border-gray-300 dark:border-gray-700 dark:bg-gray-700 dark:text-white rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              End Date
            </label>
            <input
              type="date"
              value={dateRange.endDate}
              onChange={(e) => setDateRange({...dateRange, endDate: e.target.value})}
              className="mt-1 block w-full border-gray-300 dark:border-gray-700 dark:bg-gray-700 dark:text-white rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>
          
          {activeReportType === 'charts' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Chart Type
              </label>
              <select
                value={chartType}
                onChange={(e) => setChartType(e.target.value)}
                className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-700 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md"
              >
                <option value="pie">Pie Chart</option>
                <option value="bar">Bar Chart</option>
                <option value="line">Line Chart</option>
              </select>
            </div>
          )}
          
          {(activeReportType === 'summary' || activeReportType === 'charts') && (
            <div className="md:col-span-1 flex items-end">
              <button
                onClick={exportPDF}
                disabled={isLoading}
                className="w-full flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                {isLoading ? 'Exporting...' : 'Export PDF'}
              </button>
            </div>
          )}
        </div>
        
        {/* Report Content */}
        <div className="mt-4">
          {isLoading ? (
            <div className="text-center py-10">Loading report data...</div>
          ) : (
            <>
              {activeReportType === 'summary' && reportData && (
                <div>
                  <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <h4 className="text-xl font-semibold text-gray-800 dark:text-white mb-2">
                      Expense Summary
                    </h4>
                    <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">
                      {new Date(reportData.start_date).toLocaleDateString()} to {new Date(reportData.end_date).toLocaleDateString()}
                    </p>
                    <div className="text-2xl font-bold text-primary-600 dark:text-primary-400">
                      ${reportData.total_expenses.toFixed(2)}
                    </div>
                  </div>
                  
                  <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
                    Expenses by Category
                  </h4>
                  
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                      <thead className="bg-gray-50 dark:bg-gray-700">
                        <tr>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                            Category
                          </th>
                          <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                            Amount
                          </th>
                          <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                            % of Total
                          </th>
                          <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                            Count
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        {reportData.categories.map((category) => (
                          <tr key={category.category_id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                              {category.category_name}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-500 dark:text-gray-300">
                              ${category.total.toFixed(2)}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-500 dark:text-gray-300">
                              {reportData.total_expenses === 0 
                                ? '0%' 
                                : `${((category.total / reportData.total_expenses) * 100).toFixed(1)}%`}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-500 dark:text-gray-300">
                              {category.count}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              
              {activeReportType === 'trends' && trendData && (
                <div>
                  <div className="mb-6">
                    <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
                      Spending Trends
                    </h4>
                    
                    {trendData.trends && trendData.trends.length > 0 ? (
                      <div className="space-y-3">
                        {trendData.trends.map((trend, index) => (
                          <div 
                            key={index} 
                            className={`p-3 rounded-md ${
                              trend.type === 'overall' 
                                ? trend.trend === 'increasing' 
                                  ? 'bg-red-50 text-red-700 dark:bg-red-900 dark:text-red-200' 
                                  : trend.trend === 'decreasing' 
                                    ? 'bg-green-50 text-green-700 dark:bg-green-900 dark:text-green-200'
                                    : 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                                : trend.type === 'category_increase'
                                  ? 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-200'
                                  : 'bg-green-50 text-green-700 dark:bg-green-900 dark:text-green-200'
                            }`}
                          >
                            {trend.message}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 border rounded-md text-gray-500 dark:text-gray-400">
                        Not enough data to determine spending trends. Add more expenses over time.
                      </div>
                    )}
                  </div>
                  
                  {trendData.trend_data && trendData.trend_data.periods && trendData.trend_data.periods.length > 0 && (
                    <div className="mb-6">
                      <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
                        Expense History
                      </h4>
                      
                      <div className="bg-white dark:bg-gray-800 p-4 border rounded-md">
                        <div className="h-64 flex items-center justify-center text-gray-500">
                          [Line Chart visualization would appear here]
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {trendData.category_data && Object.keys(trendData.category_data).length > 0 && (
                    <div>
                      <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
                        Category Spending Trends
                      </h4>
                      
                      <div className="bg-white dark:bg-gray-800 p-4 border rounded-md">
                        <div className="h-64 flex items-center justify-center text-gray-500">
                          [Category Trend Chart visualization would appear here]
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
              
              {activeReportType === 'charts' && chartData && (
                <div>
                  <div className="mb-6">
                    <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
                      {chartType === 'pie' 
                        ? 'Expense Distribution by Category' 
                        : chartType === 'bar' 
                          ? 'Category Comparison' 
                          : 'Expense Trend Over Time'}
                    </h4>
                    
                    <div className="bg-white dark:bg-gray-800 p-4 border rounded-md">
                      <div className="h-64 flex items-center justify-center text-gray-500">
                        [{chartType.charAt(0).toUpperCase() + chartType.slice(1)} Chart visualization would appear here]
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function SettingsTab() {
  const { token } = useAuth();
  const { colorTheme, mode, updateTheme } = useTheme();
  const [selectedTheme, setSelectedTheme] = useState(colorTheme);
  const [selectedMode, setSelectedMode] = useState(mode);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const themes = [
    { id: 'blue', name: 'Blue', color: '#3b82f6' },
    { id: 'purple', name: 'Purple', color: '#8b5cf6' },
    { id: 'green', name: 'Green', color: '#10b981' },
    { id: 'orange', name: 'Orange', color: '#f59e0b' },
  ];

  const handleSaveTheme = async () => {
    setSuccess('');
    setError('');
    
    try {
      await updateTheme(selectedTheme, selectedMode);
      setSuccess('Theme settings saved successfully!');
      
      setTimeout(() => {
        setSuccess('');
      }, 3000);
    } catch (error) {
      console.error('Error saving theme settings:', error);
      setError('Failed to save theme settings. Please try again.');
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
      <div className="px-4 py-5 sm:px-6">
        <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
          Settings
        </h3>
      </div>
      
      {success && (
        <div className="mx-4 mb-4 p-3 bg-green-50 text-green-600 rounded-md text-sm">
          {success}
        </div>
      )}
      
      {error && (
        <div className="mx-4 mb-4 p-3 bg-red-50 text-red-500 rounded-md text-sm">
          {error}
        </div>
      )}
      
      <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-5 sm:p-6">
        <div className="mb-6">
          <h4 className="text-lg font-medium text-gray-800 dark:text-white mb-3">
            Appearance
          </h4>
          
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Color Theme
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {themes.map((theme) => (
                <div
                  key={theme.id}
                  onClick={() => setSelectedTheme(theme.id)}
                  className={`p-3 border rounded-md cursor-pointer hover:border-primary-400 transition-all flex items-center ${
                    selectedTheme === theme.id 
                      ? 'border-primary-500 ring-2 ring-primary-500 dark:border-primary-400 dark:ring-primary-400' 
                      : 'border-gray-300 dark:border-gray-600'
                  }`}
                >
                  <div 
                    className="w-5 h-5 rounded-full mr-2" 
                    style={{ backgroundColor: theme.color }}
                  ></div>
                  <span className="text-gray-800 dark:text-gray-200">{theme.name}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Display Mode
            </label>
            <div className="grid grid-cols-2 gap-3">
              <div
                onClick={() => setSelectedMode('light')}
                className={`p-3 border rounded-md cursor-pointer hover:border-primary-400 transition-all flex items-center ${
                  selectedMode === 'light' 
                    ? 'border-primary-500 ring-2 ring-primary-500 dark:border-primary-400 dark:ring-primary-400' 
                    : 'border-gray-300 dark:border-gray-600'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-gray-500 dark:text-gray-300" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
                </svg>
                <span className="text-gray-800 dark:text-gray-200">Light</span>
              </div>
              <div
                onClick={() => setSelectedMode('dark')}
                className={`p-3 border rounded-md cursor-pointer hover:border-primary-400 transition-all flex items-center ${
                  selectedMode === 'dark' 
                    ? 'border-primary-500 ring-2 ring-primary-500 dark:border-primary-400 dark:ring-primary-400' 
                    : 'border-gray-300 dark:border-gray-600'
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-gray-500 dark:text-gray-300" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                </svg>
                <span className="text-gray-800 dark:text-gray-200">Dark</span>
              </div>
            </div>
          </div>
          
          <button
            onClick={handleSaveTheme}
            className="mt-4 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            Save Appearance Settings
          </button>
        </div>
      </div>
    </div>
  );
}

function LandingPage() {
  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
        <div className="text-center">
          <h1 className="text-4xl tracking-tight font-extrabold text-gray-900 dark:text-white sm:text-5xl md:text-6xl">
            <span className="block text-primary-600 dark:text-primary-400">Expense Tracker</span>
            <span className="block text-gray-700 dark:text-gray-300 text-2xl sm:text-3xl mt-2">Manage your finances with ease</span>
          </h1>
          <p className="mt-3 max-w-md mx-auto text-base text-gray-500 dark:text-gray-400 sm:text-lg md:mt-5 md:text-xl md:max-w-3xl">
            Track your expenses, visualize spending patterns, and gain control over your financial life.
          </p>
          <div className="mt-5 max-w-md mx-auto sm:flex sm:justify-center md:mt-8">
            <div className="rounded-md shadow">
              <a
                href="/register"
                className="w-full flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 md:py-4 md:text-lg md:px-10"
              >
                Get Started
              </a>
            </div>
            <div className="mt-3 rounded-md shadow sm:mt-0 sm:ml-3">
              <a
                href="/login"
                className="w-full flex items-center justify-center px-8 py-3 border border-transparent text-base font-medium rounded-md text-primary-600 bg-white hover:bg-gray-50 dark:bg-gray-800 dark:text-primary-400 dark:hover:bg-gray-700 md:py-4 md:text-lg md:px-10"
              >
                Log in
              </a>
            </div>
          </div>
        </div>
        
        <div className="mt-16">
          <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
            <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
              <div className="text-primary-600 dark:text-primary-400 text-2xl mb-3">
                Track Expenses
              </div>
              <p className="text-gray-600 dark:text-gray-300">
                Easily record and categorize your daily expenses with preset and custom categories.
              </p>
            </div>
            
            <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
              <div className="text-primary-600 dark:text-primary-400 text-2xl mb-3">
                Visualize Data
              </div>
              <p className="text-gray-600 dark:text-gray-300">
                View your spending habits through interactive charts and comprehensive reports.
              </p>
            </div>
            
            <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
              <div className="text-primary-600 dark:text-primary-400 text-2xl mb-3">
                Export Reports
              </div>
              <p className="text-gray-600 dark:text-gray-300">
                Download and share detailed PDF reports of your expenses sorted by various criteria.
              </p>
            </div>
          </div>
        </div>
      </div>
      
      <footer className="bg-gray-50 dark:bg-gray-800">
        <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
          <p className="text-center text-gray-500 dark:text-gray-400">
            &copy; 2025 Expense Tracker. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/dashboard" element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          } />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
