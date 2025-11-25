import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, Lock, Terminal } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './App.css';

const API_URL = 'http://localhost:5000/api';

function App() {
  const [stats, setStats] = useState({ totalAttacks: 0, authAttempts: 0 });
  const [recentAttacks, setRecentAttacks] = useState([]);
  const [topCredentials, setTopCredentials] = useState([]);
  const [topCommands, setTopCommands] = useState([]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [statsRes, attacksRes, credsRes, cmdsRes] = await Promise.all([
        axios.get(`${API_URL}/stats`),
        axios.get(`${API_URL}/attacks/recent`),
        axios.get(`${API_URL}/attacks/credentials`),
        axios.get(`${API_URL}/attacks/commands`)
      ]);

      setStats(statsRes.data);
      setRecentAttacks(attacksRes.data);
      setTopCredentials(credsRes.data.map(c => ({
        name: `${c._id.username}/${c._id.password}`,
        count: c.count
      })));
      setTopCommands(cmdsRes.data.map(c => ({
        name: c._id,
        count: c.count
      })));
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  const importLogs = async () => {
    try {
      const res = await axios.post(`${API_URL}/import-logs`);
      alert(res.data.message);
      loadData();
    } catch (error) {
      alert('Error importing logs: ' + error.message);
    }
  };

  return (
    <div className="App">
      <header className="header">
        <Shield size={32} />
        <h1>Honeypot Dashboard</h1>
      </header>

      <div className="container">
        {/* Stats Cards */}
        <div className="stats-grid">
          <div className="stat-card blue">
            <Activity size={24} />
            <div>
              <h3>Total Attacks</h3>
              <p className="stat-number">{stats.totalAttacks}</p>
            </div>
          </div>
          
          <div className="stat-card purple">
            <Lock size={24} />
            <div>
              <h3>Auth Attempts</h3>
              <p className="stat-number">{stats.authAttempts}</p>
            </div>
          </div>
        </div>

        {/* Import Button */}
        <button className="import-btn" onClick={importLogs}>
          📥 Import Logs from Honeypot
        </button>

        {/* Charts */}
        <div className="charts-grid">
          <div className="chart-card">
            <h2><Lock size={20} /> Top Credentials</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topCredentials}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#8b5cf6" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-card">
            <h2><Terminal size={20} /> Top Commands</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topCommands}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#ec4899" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Attacks Table */}
        <div className="table-card">
          <h2>Recent Attacks</h2>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Username</th>
                <th>Password</th>
              </tr>
            </thead>
            <tbody>
              {recentAttacks.slice(0, 10).map((attack, idx) => (
                <tr key={idx}>
                  <td>{new Date(attack.timestamp).toLocaleString()}</td>
                  <td>{attack.ip || 'N/A'}</td>
                  <td>{attack.username}</td>
                  <td>{attack.password}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default App;