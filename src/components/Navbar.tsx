import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, BarChart3, Info, Bell, Menu, X } from 'lucide-react';
import { getAlerts } from '../services/api';

const Navbar = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [unreadAlerts, setUnreadAlerts] = useState(0);

  useEffect(() => {
    // Fetch alerts to check for unread ones
    const fetchAlerts = async () => {
      try {
        const alerts = await getAlerts();
        const unreadCount = alerts .filter(alert => !alert.is_read).length;
        setUnreadAlerts(unreadCount);
      } catch (error) {
        console.error('Error fetching alerts:', error);
      }
    };

    fetchAlerts();
    
    // Set up interval to check for new alerts
    const intervalId = setInterval(fetchAlerts, 60000); // Check every minute
    
    return () => clearInterval(intervalId);
  }, []);

  return (
    <nav className="bg-indigo-600 text-white shadow-md">
      <div className="container mx-auto px-4 py-3">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-8 w-8" />
            <span className="text-xl font-bold">PhishGuard</span>
          </Link>
          
          <div className="hidden md:flex space-x-8">
            <Link to="/" className="hover:text-indigo-200 transition-colors flex items-center gap-1">
              <Shield className="h-4 w-4" />
              <span>URL Scanner</span>
            </Link>
            <Link to="/dashboard" className="hover:text-indigo-200 transition-colors flex items-center gap-1">
              <BarChart3 className="h-4 w-4" />
              <span>Dashboard</span>
            </Link>
            <Link to="/alerts" className="hover:text-indigo-200 transition-colors flex items-center gap-1 relative">
              <Bell className="h-4 w-4" />
              <span>Alerts</span>
              {unreadAlerts > 0 && (
                <span className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {unreadAlerts}
                </span>
              )}
            </Link>
            <Link to="/about" className="hover:text-indigo-200 transition-colors flex items-center gap-1">
              <Info className="h-4 w-4" />
              <span>About</span>
            </Link>
          </div>
          
          <div className="md:hidden">
            <button 
              className="p-2"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
        
        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden mt-4 space-y-4 pb-3">
            <Link 
              to="/" 
              className="block hover:text-indigo-200 transition-colors py-2"
              onClick={() => setMobileMenuOpen(false)}
            >
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span>URL Scanner</span>
              </div>
            </Link>
            <Link 
              to="/dashboard" 
              className="block hover:text-indigo-200 transition-colors py-2"
              onClick={() => setMobileMenuOpen(false)}
            >
              <div className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4" />
                <span>Dashboard</span>
              </div>
            </Link>
            <Link 
              to="/alerts" 
              className="block hover:text-indigo-200 transition-colors py-2 relative"
              onClick={() => setMobileMenuOpen(false)}
            >
              <div className="flex items-center gap-2">
                <Bell className="h-4 w-4" />
                <span>Alerts</span>
                {unreadAlerts > 0 && (
                  <span className="ml-2 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                    {unreadAlerts}
                  </span>
                )}
              </div>
            </Link>
            <Link 
              to="/about" 
              className="block hover:text-indigo-200 transition-colors py-2"
              onClick={() => setMobileMenuOpen(false)}
            >
              <div className="flex items-center gap-2">
                <Info className="h-4 w-4" />
                <span>About</span>
              </div>
            </Link>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;