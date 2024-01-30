import React, { useState } from 'react';
import './App.css';

function Notification({ message, onClose }) {
  return (
    <div className="notification">
      {message}
      <button onClick={onClose}>Close</button>
    </div>
  );
}

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [data, setData] = useState(null);
  const [isAuthenticated, setAuthenticated] = useState(false);
  const [notification, setNotification] = useState(null);

  const handleLogin = async () => {
    try {
      const response = await fetch('http://localhost:3001/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const result = await response.json();

      if (!response.ok) {
        if (response.status === 401 && result.error === 'Account locked') {
          setNotification('Account is locked. Please try again later.');
        } else {
          setNotification('Login failed. Please check your credentials and try again.');
        }
      } else {
        sessionStorage.setItem('access_token', result.token);
        setAuthenticated(true);
      }
    } catch (error) {
      setNotification('Login failed. Please try again later.');
    }
  };

  const handleLogout = () => {
    sessionStorage.removeItem('access_token');
    setAuthenticated(false);
    setData(null);
  };

  const fetchData = async () => {
    try {
      const token = sessionStorage.getItem('access_token');
      const response = await fetch('http://localhost:3002/data', {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        if (response.status === 401) {
          handleLogout();
          setNotification('Session expired. Please login again.');
          return;
        }
        setNotification('Failed to fetch data from the backend.');
      } else {
        const result = await response.json();
        setData(result.data);
      }
    } catch (error) {
      setNotification('Failed to fetch data. Please try again later.');
    }
  };

  const closeNotification = () => {
    setNotification(null);
  };

  return (
    <div className="App">
      <header className="App-header">
        {notification && <Notification message={notification} onClose={closeNotification} />}

        {isAuthenticated ? (
          <>
            {data ? <p>{data}</p> : <button onClick={fetchData}>Fetch Data</button>}
            <button onClick={handleLogout}>Logout</button>
          </>
        ) : (
          <div className="login-container">
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="input-field" />
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="input-field" />
            <button onClick={handleLogin} className="login-button">
              Login
            </button>
          </div>
        )}
      </header>
    </div>
  );
}

export default App;
