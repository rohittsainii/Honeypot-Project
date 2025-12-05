// App.js - Complete Frontend with Threat Intelligence Dashboard

import React, { useState, useEffect } from 'react';
import { 
  Shield, Activity, Globe, Lock, Terminal, TrendingUp, 
  AlertTriangle, MapPin, AlertCircle, Zap, Eye, Target,
  FileText, Database, Clock, Ban
} from 'lucide-react';
import { 
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, 
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';
import * as api from './api';
import './App.css';

function App() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview'); // overview, threats, mitre
  
  // Overview Data
  const [stats, setStats] = useState({
    totalAttacks: 0,
    authAttempts: 0,
    uniqueIps: 0,
    successfulSessions: 0,
    maliciousCommands: 0
  });
  const [recentAttacks, setRecentAttacks] = useState([]);
  const [topCredentials, setTopCredentials] = useState([]);
  const [topCommands, setTopCommands] = useState([]);
  const [attacksByCountry, setAttacksByCountry] = useState([]);
  const [timeline, setTimeline] = useState([]);
  
  // Threat Intelligence Data
  const [threatAlerts, setThreatAlerts] = useState(null);
  const [mitreMapping, setMitreMapping] = useState(null);
  const [threatSummary, setThreatSummary] = useState(null);
  
  const [importing, setImporting] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  useEffect(() => {
    loadAllData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      loadAllData();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [
        statsRes, 
        attacksRes, 
        credsRes, 
        cmdsRes, 
        countriesRes, 
        timelineRes,
        threatAlertsRes,
        mitreRes,
        summaryRes
      ] = await Promise.all([
        api.getStats(),
        api.getRecentAttacks(30),
        api.getTopCredentials(),
        api.getTopCommands(),
        api.getAttacksByCountry(),
        api.getTimeline(7),
        api.getThreatAlerts(),
        api.getMITREMapping(),
        api.getThreatSummary()
      ]);

      setStats(statsRes.data);
      setRecentAttacks(attacksRes.data);
      setTopCredentials(credsRes.data.slice(0, 10).map(c => ({
        name: `${c.username}/${c.password}`,
        count: c.count
      })));
      setTopCommands(cmdsRes.data.slice(0, 10).map(c => ({
        name: c.command.substring(0, 30),
        count: c.count
      })));
      setAttacksByCountry(countriesRes.data);
      setTimeline(timelineRes.data);
      setThreatAlerts(threatAlertsRes.data);
      setMitreMapping(mitreRes.data);
      setThreatSummary(summaryRes.data);
      
      setLastUpdate(new Date());
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
  const SEVERITY_COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e'
  };

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
          <div className="header-right">
            <div className="last-update">
              <Clock size={16} />
              <span>Updated: {lastUpdate.toLocaleTimeString()}</span>
            </div>
            <button className="import-btn" onClick={handleImportLogs} disabled={importing}>
              {importing ? 'Importing...' : 'Import Logs'}
            </button>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="nav-tabs">
        <button 
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Activity size={20} />
          Overview
        </button>
        <button 
          className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          <AlertTriangle size={20} />
          Threat Intelligence
        </button>
        <button 
          className={`tab-btn ${activeTab === 'mitre' ? 'active' : ''}`}
          onClick={() => setActiveTab('mitre')}
        >
          <Target size={20} />
          MITRE ATT&CK
        </button>
      </div>

      <div className="container">
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <>
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
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="date" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#0f172a', 
                        border: '1px solid #334155', 
                        borderRadius: '8px',
                        color: '#e5e7eb'
                      }} 
                    />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="attacks" 
                      stroke="#3b82f6" 
                      strokeWidth={3} 
                      dot={{ fill: '#3b82f6', r: 4 }} 
                      activeDot={{ r: 6 }} 
                    />
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
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" stroke="#94a3b8" />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        width={150} 
                        stroke="#94a3b8" 
                        style={{ fontSize: '12px' }} 
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#0f172a', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e5e7eb'
                        }} 
                      />
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
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis 
                        dataKey="name" 
                        angle={-45} 
                        textAnchor="end" 
                        height={100} 
                        stroke="#94a3b8" 
                        style={{ fontSize: '11px' }} 
                      />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#0f172a', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e5e7eb'
                        }} 
                      />
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
                      <Pie 
                        data={attacksByCountry} 
                        cx="50%" 
                        cy="50%" 
                        labelLine={false} 
                        label={({ country, percent }) => `${country} ${(percent * 100).toFixed(0)}%`} 
                        outerRadius={100} 
                        fill="#8884d8" 
                        dataKey="count"
                      >
                        {attacksByCountry.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#0f172a', 
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          color: '#e5e7eb'
                        }} 
                      />
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
          </>
        )}

        {/* THREAT INTELLIGENCE TAB */}
        {activeTab === 'threats' && threatAlerts && (
          <>
            {/* Threat Summary Cards */}
            <div className="threat-summary-grid">
              <div className="threat-card critical">
                <div className="threat-icon"><Ban size={32} /></div>
                <div className="threat-content">
                  <h3>Critical Alerts</h3>
                  <p className="threat-number">{threatAlerts.summary.criticalAlerts}</p>
                  <span className="threat-label">Immediate action required</span>
                </div>
              </div>
              <div className="threat-card high">
                <div className="threat-icon"><AlertCircle size={32} /></div>
                <div className="threat-content">
                  <h3>High Priority</h3>
                  <p className="threat-number">{threatAlerts.summary.highAlerts}</p>
                  <span className="threat-label">Needs investigation</span>
                </div>
              </div>
              <div className="threat-card total">
                <div className="threat-icon"><Eye size={32} /></div>
                <div className="threat-content">
                  <h3>Total Detections</h3>
                  <p className="threat-number">{threatAlerts.summary.totalAlerts}</p>
                  <span className="threat-label">All threat indicators</span>
                </div>
              </div>
              {threatSummary && (
                <div className={`threat-card risk-${threatSummary.riskLevel.toLowerCase()}`}>
                  <div className="threat-icon"><Zap size={32} /></div>
                  <div className="threat-content">
                    <h3>Risk Level</h3>
                    <p className="threat-number">{threatSummary.riskLevel}</p>
                    <span className="threat-label">Current threat status</span>
                  </div>
                </div>
              )}
            </div>

            {/* Brute Force Attacks */}
            {threatAlerts.alerts.bruteForce.count > 0 && (
              <div className="card threat-detail">
                <div className="card-header">
                  <AlertTriangle size={24} style={{ color: SEVERITY_COLORS.high }} />
                  <h2>SSH Brute Force Attacks</h2>
                  <span className="badge high">HIGH</span>
                  <span className="mitre-badge">T1110.001</span>
                </div>
                <div className="card-content">
                  <p className="threat-description">
                    Detected {threatAlerts.alerts.bruteForce.count} IP addresses performing brute force attacks
                  </p>
                  <div className="table-wrapper">
                    <table className="threats-table">
                      <thead>
                        <tr>
                          <th>IP Address</th>
                          <th>Attempts</th>
                          <th>Usernames Tried</th>
                          <th>Last Attempt</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threatAlerts.alerts.bruteForce.data.slice(0, 10).map((item, idx) => (
                          <tr key={idx}>
                            <td className="monospace">{item.ip}</td>
                            <td><span className="badge-count">{item.attempts}</span></td>
                            <td>{item.usernames.slice(0, 3).join(', ')}</td>
                            <td className="timestamp">{new Date(item.lastAttempt).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* Malicious Commands */}
            {threatAlerts.alerts.maliciousCommands.count > 0 && (
              <div className="card threat-detail">
                <div className="card-header">
                  <Terminal size={24} style={{ color: SEVERITY_COLORS.high }} />
                  <h2>Malicious Command Execution</h2>
                  <span className="badge high">HIGH</span>
                  <span className="mitre-badge">T1059</span>
                </div>
                <div className="card-content">
                  <p className="threat-description">
                    Detected {threatAlerts.alerts.maliciousCommands.count} malicious command patterns
                  </p>
                  <div className="command-categories">
                    {threatAlerts.alerts.maliciousCommands.data.map((cmd, idx) => (
                      <div key={idx} className="command-category">
                        <div className="category-header">
                          <h4>{cmd.pattern}</h4>
                          <span className={`badge ${cmd.severity}`}>{cmd.severity.toUpperCase()}</span>
                          <span className="category-count">{cmd.count} occurrences</span>
                        </div>
                        <div className="command-examples">
                          {cmd.matches.slice(0, 3).map((match, midx) => (
                            <div key={midx} className="command-example">
                              <code>{match.command}</code>
                              <span className="command-meta">
                                {match.ip} • {match.country} • {new Date(match.timestamp).toLocaleString()}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Crypto Miners */}
            {threatAlerts.alerts.cryptoMiners.count > 0 && (
              <div className="card threat-detail">
                <div className="card-header">
                  <Zap size={24} style={{ color: SEVERITY_COLORS.critical }} />
                  <h2>Cryptocurrency Miner Activity</h2>
                  <span className="badge critical">CRITICAL</span>
                  <span className="mitre-badge">T1496</span>
                </div>
                <div className="card-content">
                  <p className="threat-description">
                    ⚠️ Critical: Detected {threatAlerts.alerts.cryptoMiners.count} cryptocurrency mining attempts
                  </p>
                  <div className="table-wrapper">
                    <table className="threats-table">
                      <thead>
                        <tr>
                          <th>Command</th>
                          <th>IP Address</th>
                          <th>Country</th>
                          <th>Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threatAlerts.alerts.cryptoMiners.data.map((miner, idx) => (
                          <tr key={idx}>
                            <td><code>{miner.command.substring(0, 50)}...</code></td>
                            <td className="monospace">{miner.ip}</td>
                            <td>{miner.country}</td>
                            <td className="timestamp">{new Date(miner.timestamp).toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* Default Credentials */}
            {threatAlerts.alerts.defaultCredentials.count > 0 && (
              <div className="card threat-detail">
                <div className="card-header">
                  <Lock size={24} style={{ color: SEVERITY_COLORS.medium }} />
                  <h2>Default Credentials Usage</h2>
                  <span className="badge medium">MEDIUM</span>
                  <span className="mitre-badge">T1078.001</span>
                </div>
                <div className="card-content">
                  <p className="threat-description">
                    Detected {threatAlerts.alerts.defaultCredentials.count} attempts using default credentials
                  </p>
                  <div className="credentials-grid">
                    {threatAlerts.alerts.defaultCredentials.data.map((cred, idx) => (
                      <div key={idx} className="credential-item">
                        <div className="credential-header">
                          <span className="credential-combo">{cred.username}:{cred.password}</span>
                          <span className="badge-count">{cred.attempts} attempts</span>
                        </div>
                        <div className="credential-ips">
                          {cred.recentAttempts.map((att, aidx) => (
                            <span key={aidx} className="ip-tag">{att.ip}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Reconnaissance Activity */}
            {threatAlerts.alerts.reconnaissance.count > 0 && (
              <div className="card threat-detail">
                <div className="card-header">
                  <Eye size={24} style={{ color: SEVERITY_COLORS.medium }} />
                  <h2>Reconnaissance Activity</h2>
                  <span className="badge medium">MEDIUM</span>
                  <span className="mitre-badge">T1046</span>
                </div>
                <div className="card-content">
                  <p className="threat-description">
                    Detected {threatAlerts.alerts.reconnaissance.count} sessions with reconnaissance commands
                  </p>
                  <div className="recon-sessions">
                    {threatAlerts.alerts.reconnaissance.data.slice(0, 5).map((session, idx) => (
                      <div key={idx} className="recon-session">
                        <div className="session-header">
                          <span className="session-ip">{session.ip}</span>
                          <span className="session-country">{session.country}</span>
                          <span className="badge-count">{session.commandCount} commands</span>
                        </div>
                        <div className="session-commands">
                          {session.commands.map((cmd, cidx) => (
                            <code key={cidx}>{cmd}</code>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* MITRE ATT&CK TAB */}
        {activeTab === 'mitre' && mitreMapping && (
          <>
            <div className="card">
              <div className="card-header">
                <Target size={24} />
                <h2>MITRE ATT&CK Framework Mapping</h2>
              </div>
              <div className="card-content">
                <p className="mitre-intro">
                  Mapping detected threats to the MITRE ATT&CK framework helps understand attacker tactics, 
                  techniques, and procedures (TTPs). Total techniques detected: <strong>{mitreMapping.totalTechniques}</strong>
                </p>
                
                <div className="mitre-stats">
                  <div className="mitre-stat">
                    <Database size={32} />
                    <div>
                      <h3>{mitreMapping.totalTechniques}</h3>
                      <p>Techniques Detected</p>
                    </div>
                  </div>
                  <div className="mitre-stat">
                    <FileText size={32} />
                    <div>
                      <h3>{mitreMapping.totalDetections}</h3>
                      <p>Total Detections</p>
                    </div>
                  </div>
                </div>

                <div className="mitre-techniques">
                  {mitreMapping.techniques.map((tech, idx) => (
                    <div key={idx} className="mitre-technique-card">
                      <div className="technique-header">
                        <div>
                          <h3>{tech.technique}</h3>
                          <h4>{tech.name}</h4>
                        </div>
                        <span className="detection-count">{tech.detections} detections</span>
                      </div>
                      <div className="technique-tactic">
                        <span className="tactic-badge">{tech.tactic}</span>
                      </div>
                      <div className="technique-bar">
                        <div 
                          className="technique-progress" 
                          style={{ 
                            width: `${(tech.detections / mitreMapping.totalDetections) * 100}%`,
                            backgroundColor: COLORS[idx % COLORS.length]
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* MITRE Radar Chart */}
            <div className="card">
              <div className="card-header">
                <Target size={24} />
                <h2>Tactics Coverage</h2>
              </div>
              <div className="card-content">
                <ResponsiveContainer width="100%" height={400}>
                  <RadarChart data={mitreMapping.techniques}>
                    <PolarGrid stroke="#334155" />
                    <PolarAngleAxis dataKey="tactic" stroke="#94a3b8" />
                    <PolarRadiusAxis stroke="#94a3b8" />
                    <Radar 
                      name="Detections" 
                      dataKey="detections" 
                      stroke="#3b82f6" 
                      fill="#3b82f6" 
                      fillOpacity={0.6} 
                    />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: '#0f172a', 
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        color: '#e5e7eb'
                      }} 
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top Attackers */}
            {threatSummary && (
              <div className="card">
                <div className="card-header">
                  <Globe size={24} />
                  <h2>Top Threat Actors</h2>
                </div>
                <div className="card-content">
                  <div className="top-attackers">
                    {threatSummary.topAttackers.map((attacker, idx) => (
                      <div key={idx} className="attacker-card">
                        <div className="attacker-rank">#{idx + 1}</div>
                        <div className="attacker-info">
                          <span className="attacker-ip">{attacker.ip}</span>
                          <span className="attacker-country">{attacker.country || 'Unknown'}</span>
                        </div>
                        <div className="attacker-attacks">
                          <span className="badge-count">{attacker.attacks} attacks</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <footer className="footer">
        <p>Honeypot Project © 2025 | UPES Computer Science</p>
        <p>Built by Rohit Saini, KM Anjali, Sunil Kumar Yadav, Bhumi Saraswat</p>
      </footer>
    </div>
  );
}

export default App;