import React, { useEffect, useState } from 'react';
import { getAlerts, markAlertsAsRead } from '../services/api';
import { AlertTriangle, CheckCircle, Bell, Clock } from 'lucide-react';

interface Alert {
  id: number;
  url: string;
  risk_level: string;
  message: string;
  is_read: boolean;
  created_at: string;
}

const Alerts = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([]);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await getAlerts();
      setAlerts(data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAlert = (id: number) => {
    if (selectedAlerts.includes(id)) {
      setSelectedAlerts(selectedAlerts.filter(alertId => alertId !== id));
    } else {
      setSelectedAlerts([...selectedAlerts, id]);
    }
  };

  const handleSelectAll = () => {
    if (selectedAlerts.length === alerts.length) {
      setSelectedAlerts([]);
    } else {
      setSelectedAlerts(alerts.map(alert => alert.id));
    }
  };

  const handleMarkAsRead = async () => {
    if (selectedAlerts.length === 0) return;
    
    try {
      await markAlertsAsRead(selectedAlerts);
      
      // Update local state
      setAlerts(alerts.map(alert => 
        selectedAlerts.includes(alert.id) 
          ? { ...alert, is_read: true } 
          : alert
      ));
      
      setSelectedAlerts([]);
    } catch (error) {
      console.error('Error marking alerts as read:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-12">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-800 flex items-center">
            <Bell className="h-8 w-8 mr-3 text-indigo-600" />
            Alerts
          </h1>
          
          {alerts.length > 0 && (
            <div className="flex space-x-4">
              <button
                onClick={handleSelectAll}
                className="px-4 py-2 text-sm font-medium text-indigo-600 hover:text-indigo-800"
              >
                {selectedAlerts.length === alerts.length ? 'Deselect All' : 'Select All'}
              </button>
              
              <button
                onClick={handleMarkAsRead}
                disabled={selectedAlerts.length === 0}
                className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
              >
                Mark as Read
              </button>
            </div>
          )}
        </div>
        
        {alerts.length === 0 ? (
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-800 mb-2">No Alerts</h2>
            <p className="text-gray-600">
              You don't have any alerts at the moment. Alerts will appear here when high-risk phishing URLs are detected.
            </p>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-10">
                      <input
                        type="checkbox"
                        checked={selectedAlerts.length === alerts.length}
                        onChange={handleSelectAll}
                        className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                      />
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alert</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {alerts.map((alert) => (
                    <tr 
                      key={alert.id} 
                      className={`${!alert.is_read ? 'bg-indigo-50' : ''} hover:bg-gray-50`}
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <input
                          type="checkbox"
                          checked={selectedAlerts.includes(alert.id)}
                          onChange={() => handleSelectAlert(alert.id)}
                          className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                        />
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-start">
                          <AlertTriangle className={`h-5 w-5 mr-3 flex-shrink-0 ${
                            alert.risk_level === 'high' ? 'text-red-500' : 
                            alert.risk_level === 'medium' ? 'text-yellow-500' : 'text-orange-500'
                          }`} />
                          <div>
                            <p className="text-sm font-medium text-gray-900">{alert.message}</p>
                            <p className="text-sm text-gray-500 truncate max-w-xs">{alert.url}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          alert.risk_level === 'high' ? 'bg-red-100 text-red-800' : 
                          alert.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800' : 
                          'bg-orange-100 text-orange-800'
                        }`}>
                          {alert.risk_level.charAt(0).toUpperCase() + alert.risk_level.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <div className="flex items-center">
                          <Clock className="h-4 w-4 mr-1 text-gray-400" />
                          {new Date(alert.created_at).toLocaleString()}
                        </div>
                      </td>
                     </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;