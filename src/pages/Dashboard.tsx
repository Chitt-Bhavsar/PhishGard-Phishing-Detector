import React, { useEffect, useState } from 'react';
import { Bar, Pie, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';
import { getUrlStats, getRecentScans, getHeatmapData } from '../services/api';
import { Clock, AlertTriangle, CheckCircle, TrendingUp, Globe } from 'lucide-react';
import HeatMap from '../components/HeatMap';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
);

const Dashboard = () => {
  const [stats, setStats] = useState<any>(null);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [heatmapData, setHeatmapData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsData = await getUrlStats();
        const scansData = await getRecentScans();
        const heatmapResult = await getHeatmapData();
        
        setStats(statsData);
        setRecentScans(scansData);
        setHeatmapData(heatmapResult);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  const barChartData = {
    labels: ['Last 7 Days', 'Last 30 Days', 'All Time'],
    datasets: [
      {
        label: 'Safe URLs',
        data: [stats?.last_7_days?.safe || 0, stats?.last_30_days?.safe || 0, stats?.all_time?.safe || 0],
        backgroundColor: 'rgba(34, 197, 94, 0.6)',
      },
      {
        label: 'Phishing URLs',
        data: [stats?.last_7_days?.phishing || 0, stats?.last_30_days?.phishing || 0, stats?.all_time?.phishing || 0],
        backgroundColor: 'rgba(239, 68, 68, 0.6)',
      },
    ],
  };

  const pieChartData = {
    labels: ['Safe', 'Phishing'],
    datasets: [
      {
        data: [stats?.all_time?.safe || 0, stats?.all_time?.phishing || 0],
        backgroundColor: ['rgba(34, 197, 94, 0.6)', 'rgba(239, 68, 68, 0.6)'],
        borderColor: ['rgb(34, 197, 94)', 'rgb(239, 68, 68)'],
        borderWidth: 1,
      },
    ],
  };

  // Prepare data for daily trend chart
  const dailyTrendData = {
    labels: stats?.daily_stats?.map((day: any) => day.date) || [],
    datasets: [
      {
        label: 'Safe URLs',
        data: stats?.daily_stats?.map((day: any) => day.safe) || [],
        borderColor: 'rgb(34, 197, 94)',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Phishing URLs',
        data: stats?.daily_stats?.map((day: any) => day.phishing) || [],
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  // Prepare data for confidence score distribution
  const confidenceScoreData = {
    labels: Object.keys(stats?.confidence_score_distribution || {}),
    datasets: [
      {
        label: 'URLs',
        data: Object.values(stats?.confidence_score_distribution || {}),
        backgroundColor: [
          'rgba(34, 197, 94, 0.6)',
          'rgba(250, 204, 21, 0.6)',
          'rgba(249, 115, 22, 0.6)',
          'rgba(239, 68, 68, 0.6)',
        ],
      },
    ],
  };

  return (
    <div className="container mx-auto px-4 py-12">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-800 mb-8">Dashboard</h1>
        
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-500 mb-2">Total URLs Scanned</h3>
            <p className="text-3xl font-bold">{stats?.all_time?.total || 0}</p>
            <div className="mt-2 text-sm text-gray-500">
              <span className="text-indigo-600 font-medium">+{stats?.last_7_days?.total || 0}</span> in the last 7 days
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-500 mb-2">Phishing URLs Detected</h3>
            <p className="text-3xl font-bold text-red-600">{stats?.all_time?.phishing || 0}</p>
            <div className="mt-2 text-sm text-gray-500">
              <span className="text-red-600 font-medium">+{stats?.last_7_days?.phishing || 0}</span> in the last 7 days
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-medium text-gray-500 mb-2">Safe URLs</h3>
            <p className="text-3xl font-bold text-green-600">{stats?.all_time?.safe || 0}</p>
            <div className="mt-2 text-sm text-gray-500">
              <span className="text-green-600 font-medium">+{stats?.last_7_days?.safe || 0}</span> in the last 7 days
            </div>
          </div>
        </div>
        
        {/* Charts - First Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-xl font-semibold mb-4">URL Scan Results</h3>
            <div className="h-64">
              <Bar 
                data={barChartData} 
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      position: 'top',
                    },
                    title: {
                      display: false,
                    },
                  },
                }}
              />
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-xl font-semibold mb-4">Overall Distribution</h3>
            <div className="h-64 flex justify-center">
              <div style={{ maxWidth: '250px' }}>
                <Pie 
                  data={pieChartData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'bottom',
                      },
                    },
                  }}
                />
              </div>
            </div>
          </div>
        </div>
        
        {/* Charts - Second Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-xl font-semibold mb-4 flex items-center">
              <TrendingUp className="h-5 w-5 mr-2 text-indigo-600" />
              Daily Trend (Last 30 Days)
            </h3>
            <div className="h-64">
              <Line 
                data={dailyTrendData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      position: 'top',
                    },
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                    },
                  },
                }}
              />
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-xl font-semibold mb-4 flex items-center">
              <Globe className="h-5 w-5 mr-2 text-indigo-600" />
              Confidence Score Distribution
            </h3>
            <div className="h-64">
              <Bar
                data={confidenceScoreData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      display: false,
                    },
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                    },
                  },
                }}
              />
            </div>
          </div>
        </div>
        
        {/* Heatmap */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h3 className="text-xl font-semibold mb-4">URL Scan Activity Heatmap (Last 30 Days)</h3>
          <div className="h-64">
            <HeatMap data={heatmapData} />
          </div>
        </div>
        
        {/* Top Phishing Domains */}
        {stats?.top_phishing_domains && stats.top_phishing_domains.length > 0 && (
          <div className="bg-white rounded-lg shadow p-6 mb-8">
            <h3 className="text-xl font-semibold mb-4">Top Phishing Domains</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Detections</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {stats.top_phishing_domains.map((domain: any, index: number) => (
                    <tr key={index}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {domain.domain}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {domain.count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        
        {/* Recent Scans */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-xl font-semibold">Recent Scans</h3>
          </div>
          
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Result</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Confidence</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Intel</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {recentScans.map((scan, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 max-w-xs truncate">
                      {scan.url}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        scan.is_phishing 
                          ? 'bg-red-100 text-red-800' 
                          : 'bg-green-100 text-green-800'
                      }`}>
                        {scan.is_phishing ? (
                          <>
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Phishing
                          </>
                        ) : (
                          <>
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Safe
                          </>
                        )}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.confidence_score}%
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.threat_intel_results && scan.threat_intel_results.some((result: any) => result.is_malicious) ? (
                        <span className="text-red-600 font-medium">Flagged</span>
                      ) : (
                        <span className="text-green-600">Clear</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 flex items-center">
                      <Clock className="h-3 w-3 mr-1" />
                      {new Date(scan.scan_date).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;