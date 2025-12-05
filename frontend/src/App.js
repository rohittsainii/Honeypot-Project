import React, { useState, useEffect } from 'react';
import { Shield, Activity, Globe, Lock, Terminal, TrendingUp, AlertTriangle, MapPin } from 'lucide-react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import * as api from './api';
import './App.css';

function App() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalAttacks: 0,
    authAttempts: 0,
    uniqueIps: 0,
    successfulSessions: 0
  });
  const [recentAttacks, setRecentAttacks] = useState([]);
  const [topCredentials, setTopCredentials] = useState([]);
  const [topCommands, setTopCommands] = useState([]);
  const [attacksByCountry, setAttacksByCountry] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [importing, setImporting] = useState(false);

  
  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [statsRes, attacksRes, credsRes, cmdsRes, countriesRes, timelineRes] = await Promise.all([
        api.getStats(),
        api.getRecentAttacks(30),
        api.getTopCredentials(),
        api.getTopCommands(),
        api.getAttacksByCountry(),
        api.getTimeline(7)
      ]);

      setStats(statsRes.data);
      setRecentAttacks(attacksRes.data);
      setTopCredentials(credsRes.data.slice(0, 10).map(c => ({
        name: `${c.username}/${c.password}`,
        count: c.count
      })));
      setTopCommands(cmdsRes.data.slice(0, 10).map(c => ({
        name: c.command,
        count: c.count
      })));
      setAttacksByCountry(countriesRes.data);
      setTimeline(timelineRes.data);
    } catch (error) {
      console.error('Error loading data:', error);
      alert('Failed to load data. Make sure backend is running on http://localhost:5000');
    } finally {
      setLoading(false);
    }
  };

  const handleImportLogs = async () => {
    if (!window.confirm('Import logs from honeypot? This may take a few minutes.')) {
      return;
    }

    setImporting(true);
    try {
      const response = await api.importLogs();
      alert(response.data.message);
      loadAllData();
    } catch (error) {
      alert('Import failed: ' + (error.response?.data?.error || error.message));
    } finally {
      setImporting(false);
    }
  };

  const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4'];

  if (loading) {
    return (
      <div className="loading-screen">
        <Shield size={48} className="spin" />
        <h2>Loading Dashboard...</h2>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="header">
        <div className="header-content">
          <div className="header-left">
            <Shield size={36} />
            <div>
              <h1>Decoy Defense</h1>
              <p>Honeypot Threat Intelligence Platform</p>
            </div>
          </div>
          <button className="import-btn" onClick={handleImportLogs} disabled={importing}>
            {importing ? '⏳ Importing...' : '📥 Import Logs'}
          </button>
        </div>
      </header>

      <div className="container">
        <div className="stats-grid">
          <div className="stat-card blue">
            <div className="stat-icon"><Activity size={28} /></div>
            <div className="stat-content">
              <h3>Total Attacks</h3>
              <p className="stat-number">{stats.totalAttacks.toLocaleString()}</p>
              <span className="stat-label">All captured events</span>
            </div>
          </div>
          <div className="stat-card purple">
            <div className="stat-icon"><Lock size={28} /></div>
            <div className="stat-content">
              <h3>Auth Attempts</h3>
              <p className="stat-number">{stats.authAttempts.toLocaleString()}</p>
              <span className="stat-label">Login attempts</span>
            </div>
          </div>
          <div className="stat-card pink">
            <div className="stat-icon"><Globe size={28} /></div>
            <div className="stat-content">
              <h3>Unique IPs</h3>
              <p className="stat-number">{stats.uniqueIps.toLocaleString()}</p>
              <span className="stat-label">Distinct attackers</span>
            </div>
          </div>
          <div className="stat-card green">
            <div className="stat-icon"><Terminal size={28} /></div>
            <div className="stat-content">
              <h3>Sessions</h3>
              <p className="stat-number">{stats.successfulSessions.toLocaleString()}</p>
              <span className="stat-label">Successful logins</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <TrendingUp size={24} />
            <h2>Attack Timeline (Last 7 Days)</h2>
          </div>
          <div className="card-content">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="date" stroke="#6b7280" />
                <YAxis stroke="#6b7280" />
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }} />
                <Legend />
                <Line type="monotone" dataKey="attacks" stroke="#3b82f6" strokeWidth={3} dot={{ fill: '#3b82f6', r: 4 }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="charts-grid">
          <div className="card">
            <div className="card-header">
              <Lock size={24} />
              <h2>Top Credentials Used</h2>
            </div>
            <div className="card-content">
              <ResponsiveContainer width="100%" height={350}>
                <BarChart data={topCredentials} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis type="number" stroke="#6b7280" />
                  <YAxis dataKey="name" type="category" width={120} stroke="#6b7280" style={{ fontSize: '12px' }} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[0, 8, 8, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <Terminal size={24} />
              <h2>Top Commands Executed</h2>
            </div>
            <div className="card-content">
              <ResponsiveContainer width="100%" height={350}>
                <BarChart data={topCommands}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} stroke="#6b7280" style={{ fontSize: '12px' }} />
                  <YAxis stroke="#6b7280" />
                  <Tooltip />
                  <Bar dataKey="count" fill="#ec4899" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <MapPin size={24} />
            <h2>Attacks by Country</h2>
          </div>
          <div className="card-content">
            <div className="country-chart">
              <ResponsiveContainer width="50%" height={300}>
                <PieChart>
                  <Pie data={attacksByCountry} cx="50%" cy="50%" labelLine={false} label={({ country, percent }) => `${country} ${(percent * 100).toFixed(0)}%`} outerRadius={100} fill="#8884d8" dataKey="count">
                    {attacksByCountry.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="country-list">
                {attacksByCountry.map((item, idx) => (
                  <div key={idx} className="country-item">
                    <div className="country-color" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                    <span className="country-name">{item.country}</span>
                    <span className="country-count">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <AlertTriangle size={24} />
            <h2>Recent Attack Attempts</h2>
          </div>
          <div className="card-content">
            <div className="table-wrapper">
              <table className="attacks-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>City</th>
                    <th>Username</th>
                    <th>Password</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAttacks.length === 0 ? (
                    <tr><td colSpan="6" className="no-data">No attacks yet. Click "Import Logs" to load data.</td></tr>
                  ) : (
                    recentAttacks.map((attack, idx) => (
                      <tr key={idx}>
                        <td className="timestamp">{new Date(attack.timestamp).toLocaleString()}</td>
                        <td className="monospace">{attack.ip || 'N/A'}</td>
                        <td>{attack.country || 'Unknown'}</td>
                        <td>{attack.city || 'Unknown'}</td>
                        <td className="monospace username">{attack.username || 'N/A'}</td>
                        <td className="monospace password">{attack.password || 'N/A'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <footer className="footer">
        <p>Honeypot Project © 2025 | UPES Computer Science</p>
        <p>Built by Rohit Saini, KM Anjali, Sunil Kumar Yadav, Bhumi Saraswat</p>
      </footer>
    </div>
  );
}

export default App;