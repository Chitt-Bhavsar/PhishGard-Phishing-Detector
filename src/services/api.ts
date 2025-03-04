import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

// For development/demo purposes, we'll simulate API responses
const simulateApiCall = (endpoint: string, data?: any) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (endpoint === '/analyze') {
        // Simulate URL analysis
        const url = data.url.toLowerCase();
        
        // Simple heuristic for demo purposes
        const isPhishing = 
          url.includes('secure') && !url.includes('https') ||
          url.includes('login') && url.includes('verify') ||
          url.includes('paypal') && !url.includes('paypal.com') ||
          url.includes('bank') && url.includes('confirm') ||
          url.includes('password') && url.includes('reset') ||
          Math.random() < 0.3; // 30% chance of being flagged as phishing
        
        const confidenceScore = isPhishing 
          ? Math.floor(70 + Math.random() * 30) 
          : Math.floor(75 + Math.random() * 25);
        
        // Generate analysis details
        const analysisDetails = [];
        
        if (!url.startsWith('https')) {
          analysisDetails.push({
            description: 'Connection is not secure (HTTP instead of HTTPS)',
            risk_level: 'high'
          });
        }
        
        if (url.includes('paypal') && !url.includes('paypal.com')) {
          analysisDetails.push({
            description: 'Domain spoofing detected - attempting to mimic PayPal',
            risk_level: 'high'
          });
        }
        
        if (url.includes('login') && url.includes('verify')) {
          analysisDetails.push({
            description: 'URL contains suspicious keywords often used in phishing',
            risk_level: 'medium'
          });
        }
        
        if (url.length > 30) {
          analysisDetails.push({
            description: 'URL length is unusually long',
            risk_level: isPhishing ? 'medium' : 'low'
          });
        }
        
        if (!isPhishing && analysisDetails.length === 0) {
          analysisDetails.push({
            description: 'Domain has good reputation and no suspicious patterns',
            risk_level: 'low'
          });
        }
        
        // Generate threat intelligence results
        const threatIntelResults = [
          {
            source: 'Google Safe Browsing',
            is_malicious: isPhishing && Math.random() < 0.7,
            details: isPhishing && Math.random() < 0.7 
              ? 'URL identified as social engineering' 
              : 'URL not found in Google Safe Browsing database'
          },
          {
            source: 'VirusTotal',
            is_malicious: isPhishing && Math.random() < 0.6,
            malicious_count: isPhishing ? Math.floor(Math.random() * 10) + 5 : 0,
            total_engines: 68,
            details: isPhishing && Math.random() < 0.6 
              ? `${Math.floor(Math.random() * 10) + 5} out of 68 security vendors flagged this URL as malicious` 
              : '0 out of 68 security vendors flagged this URL as malicious'
          },
          {
            source: 'PhishTank',
            is_malicious: isPhishing && Math.random() < 0.5,
            details: isPhishing && Math.random() < 0.5 
              ? 'URL found in PhishTank database as a confirmed phishing site' 
              : 'URL not found in PhishTank database'
          }
        ];
        
        // Generate WHOIS data
        const creationDate = new Date();
        creationDate.setDate(creationDate.getDate() - (isPhishing ? Math.floor(Math.random() * 60) + 1 : Math.floor(Math.random() * 1000) + 100));
        
        const whoisData = {
          registrar: isPhishing ? 'NameCheap, Inc.' : 'GoDaddy.com, LLC',
          creation_date: creationDate.toISOString(),
          expiration_date: new Date(creationDate.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          domain_age_days: Math.floor((new Date().getTime() - creationDate.getTime()) / (24 * 60 * 60 * 1000)),
          is_new_domain: Math.floor((new Date().getTime() - creationDate.getTime()) / (24 * 60 * 60 * 1000)) < 90,
          registrant: isPhishing ? 'REDACTED FOR PRIVACY' : 'Example Organization',
          registrant_country: isPhishing ? 'RU' : 'US'
        };
        
        // Generate SSL certificate info
        const sslInfo = {
          has_ssl: url.startsWith('https') || Math.random() > 0.3,
          issuer: url.startsWith('https') || Math.random() > 0.3 
            ? (isPhishing ? 'Let\'s Encrypt Authority X3' : 'DigiCert Inc') 
            : null,
          subject: url.startsWith('https') || Math.random() > 0.3 
            ? (url.includes('www.') ? url.substring(url.indexOf('www.')) : url.substring(url.indexOf('://') + 3)) 
            : null,
          valid_from: new Date(creationDate.getTime() + 24 * 60 * 60 * 1000).toISOString(),
          valid_until: new Date(creationDate.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString(),
          is_expired: false,
          is_self_signed: isPhishing && Math.random() < 0.3,
          cert_age_days: 30,
          validity_period_days: isPhishing ? 90 : 365,
          is_short_lived: isPhishing
        };
        
        // Generate content analysis
        const contentAnalysis = {
          has_login_form: isPhishing || url.includes('login') || Math.random() < 0.5,
          password_input_count: isPhishing || url.includes('login') ? 1 : 0,
          has_suspicious_scripts: isPhishing && Math.random() < 0.7,
          suspicious_scripts: isPhishing && Math.random() < 0.7 ? [
            {
              type: 'Obfuscated JavaScript',
              snippet: 'eval(function(p,a,c,k,e,d){e=function(c){return c};if(!'
            }
          ] : [],
          external_resource_count: isPhishing ? Math.floor(Math.random() * 10) + 3 : Math.floor(Math.random() * 5) + 1,
          external_resources: ['cdn.example.com', 'analytics.example.com', 'fonts.googleapis.com'],
          brand_mentions: isPhishing ? ['paypal', 'bank', 'account'] : [],
          security_keyword_count: isPhishing ? Math.floor(Math.random() * 5) + 2 : Math.floor(Math.random() * 2),
          page_title: isPhishing ? 'Secure Login - Verify Your Account' : 'Welcome to Example.com',
          content_length: Math.floor(Math.random() * 50000) + 10000
        };
        
        resolve({
          url: data.url,
          is_phishing: isPhishing,
          confidence_score: confidenceScore,
          analysis_details: analysisDetails,
          threat_intel_results: threatIntelResults,
          whois_data: whoisData,
          ssl_info: sslInfo,
          content_analysis: contentAnalysis
        });
      } else if (endpoint === '/stats') {
        // Simulate stats data
        const last7DaysSafe = Math.floor(Math.random() * 30) + 20;
        const last7DaysPhishing = Math.floor(Math.random() * 15) + 5;
        const last30DaysSafe = Math.floor(Math.random() * 100) + 80;
        const last30DaysPhishing = Math.floor(Math.random() * 50) + 20;
        const allTimeSafe = Math.floor(Math.random() * 1000) + 500;
        const allTimePhishing = Math.floor(Math.random() * 500) + 100;
        
        // Generate daily stats for the last 30 days
        const dailyStats = [];
        const today = new Date();
        
        for (let i = 29; i >= 0; i--) {
          const date = new Date(today);
          date.setDate(date.getDate() - i);
          const dateString = date.toISOString().split('T')[0];
          
          const dailySafe = Math.floor(Math.random() * 10) + 1;
          const dailyPhishing = Math.floor(Math.random() * 5);
          
          dailyStats.push({
            date: dateString,
            total: dailySafe + dailyPhishing,
            safe: dailySafe,
            phishing: dailyPhishing
          });
        }
        
        // Generate confidence score distribution
        const confidenceScoreDistribution = {
          '0-25': Math.floor(Math.random() * 100) + 50,
          '26-50': Math.floor(Math.random() * 200) + 100,
          '51-75': Math.floor(Math.random() * 300) + 150,
          '76-100': Math.floor(Math.random() * 400) + 200
        };
        
        // Generate top phishing domains
        const topPhishingDomains = [
          { domain: 'secure-paypal-login.com', count: Math.floor(Math.random() * 20) + 10 },
          { domain: 'account-verify-service.net', count: Math.floor(Math.random() * 15) + 8 },
          { domain: 'banking-secure-login.com', count: Math.floor(Math.random() * 12) + 6 },
          { domain: 'netflix-account-update.com', count: Math.floor(Math.random() * 10) + 5 },
          { domain: 'amazon-order-confirm.net', count: Math.floor(Math.random() * 8) + 4 },
          { domain: 'microsoft365-password-reset.com', count: Math.floor(Math.random() * 7) + 3 },
          { domain: 'google-security-alert.com', count: Math.floor(Math.random() * 6) + 2 },
          { domain: 'apple-id-confirm.net', count: Math.floor(Math.random() * 5) + 2 },
          { domain: 'facebook-login-secure.com', count: Math.floor(Math.random() * 4) + 1 },
          { domain: 'instagram-verify-account.net', count: Math.floor(Math.random() * 3) + 1 }
        ];
        
        resolve({
          last_7_days: {
            total: last7DaysSafe + last7DaysPhishing,
            phishing: last7DaysPhishing,
            safe: last7DaysSafe
          },
          last_30_days: {
            total: last30DaysSafe + last30DaysPhishing,
            phishing: last30DaysPhishing,
            safe: last30DaysSafe
          },
          all_time: {
            total: allTimeSafe + allTimePhishing,
            phishing: allTimePhishing,
            safe: allTimeSafe
          },
          daily_stats: dailyStats,
          confidence_score_distribution: confidenceScoreDistribution,
          top_phishing_domains: topPhishingDomains
        });
      } else if (endpoint === '/recent') {
        // Simulate recent scans
        const scans = [];
        const domains = [
          'example.com', 
          'secure-login-verify.com', 
          'paypal-secure.net', 
          'amazon.com', 
          'facebook.com',
          'bank-verify-account.com',
          'netflix.com',
          'google.com',
          'microsoft-password-reset.net',
          'apple-id-confirm.net'
        ];
        
        for (let i = 0; i < 10; i++) {
          const domain = domains[Math.floor(Math.random() * domains.length)];
          const isPhishing = 
            domain.includes('verify') || 
            domain.includes('secure-login') || 
            domain.includes('paypal-secure') ||
            domain.includes('password-reset') ||
            domain.includes('confirm');
          
          const confidenceScore = isPhishing ? 
            Math.floor(75 + Math.random() * 25) : 
            Math.floor(80 + Math.random() * 20);
          
          // Generate threat intelligence results
          const threatIntelResults = [
            {
              source: 'Google Safe Browsing',
              is_malicious: isPhishing && Math.random() < 0.7,
              details: isPhishing && Math.random() < 0.7 
                ? 'URL identified as social engineering' 
                : 'URL not found in Google Safe Browsing database'
            },
            {
              source: 'VirusTotal',
              is_malicious: isPhishing && Math.random() < 0.6,
              details: isPhishing && Math.random() < 0.6 
                ? `${Math.floor(Math.random() * 10) + 5} out of 68 security vendors flagged this URL as malicious` 
                : '0 out of 68 security vendors flagged this URL as malicious'
            },
            {
              source: 'PhishTank',
              is_malicious: isPhishing && Math.random() < 0.5,
              details: isPhishing && Math.random() < 0.5 
                ? 'URL found in PhishTank database as a confirmed phishing site' 
                : 'URL not found in PhishTank database'
            }
          ];
          
          scans.push({
            url: `https://${domain}/` + (isPhishing ? 'login?secure=1&verify=true' : ''),
            is_phishing: isPhishing,
            confidence_score: confidenceScore,
            analysis_details: [
              {
                description: isPhishing 
                  ? 'URL contains suspicious keywords often used in phishing' 
                  : 'No suspicious patterns detected in URL',
                risk_level: isPhishing ? 'medium' : 'low'
              }
            ],
            threat_intel_results: threatIntelResults,
            scan_date: new Date(Date.now() - Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000)).toISOString()
          });
        }
        
        resolve(scans);
      } else if (endpoint === '/alerts') {
        // Simulate alerts
        const alerts = [];
        const riskLevels = ['high', 'medium', 'high', 'high', 'medium'];
        const urls = [
          'https://secure-paypal-login.com/verify?id=12345',
          'https://account-verify-service.net/login',
          'https://banking-secure-login.com/confirm',
          'https://netflix-account-update.com/password',
          'https://amazon-order-confirm.net/order/123456'
        ];
        const messages = [
          'High-risk phishing URL detected with 92% confidence',
          'Suspicious login page detected with multiple security issues',
          'Domain spoofing detected - attempting to mimic banking website',
          'Phishing URL detected by multiple threat intelligence sources',
          'Suspicious URL with obfuscated JavaScript detected'
        ];
        
        for (let i = 0; i < 5; i++) {
          const createdAt = new Date();
          createdAt.setHours(createdAt.getHours() - Math.floor(Math.random() * 48));
          
          alerts.push({
            id: i + 1,
            url: urls[i],
            risk_level: riskLevels[i],
            message: messages[i],
            is_read: Math.random() > 0.6,
            created_at: createdAt.toISOString()
          });
        }
        
        resolve(alerts);
      } else if (endpoint === '/alerts/mark-read') {
        // Simulate marking alerts as read
        resolve({
          success: true,
          message: `${data.alert_ids.length} alerts marked as read`
        });
      } else if (endpoint === '/heatmap') {
        // Simulate heatmap data
        const heatmapData = [];
        const today = new Date();
        
        for (let i = 29; i >= 0; i--) {
          const date = new Date(today);
          date.setDate(date.getDate() - i);
          const dateString = date.toISOString().split('T')[0];
          
          // Generate random count with some days having higher activity
          let count;
          if (i % 7 === 0) {
            // Weekends have more activity
            count = Math.floor(Math.random() * 20) + 10;
          } else {
            count = Math.floor(Math.random() * 10) + 1;
          }
          
          heatmapData.push({
            date: dateString,
            count: count
          });
        }
        
        resolve(heatmapData);
      }
    }, 1000); // Simulate network delay
  });
};

// Analyze a URL
export const analyzeUrl = async (url: string) => {
  try {
    // In a real app, we would use this:
    // const response = await axios.post(`${API_URL}/analyze`, { url });
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/analyze', { url });
  } catch (error) {
    console.error('Error analyzing URL:', error);
    throw error;
  }
};

// Get URL statistics
export const getUrlStats = async () => {
  try {
    // In a real app, we would use this:
    // const response = await axios.get(`${API_URL}/stats`);
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/stats');
  } catch (error) {
    console.error('Error fetching URL stats:', error);
    throw error;
  }
};

// Get recent URL scans
export const getRecentScans = async () => {
  try {
    // In a real app, we would use this:
    // const response = await axios.get(`${API_URL}/recent`);
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/recent');
  } catch (error) {
    console.error('Error fetching recent scans:', error);
    throw error;
  }
};

// Get alerts
export const getAlerts = async () => {
  try {
    // In a real app, we would use this:
    // const response = await axios.get(`${API_URL}/alerts`);
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/alerts');
  } catch (error) {
    console.error('Error fetching alerts:', error);
    throw error;
  }
};

// Mark alerts as read
export const markAlertsAsRead = async (alertIds: number[]) => {
  try {
    // In a real app, we would use this:
    // const response = await axios.post(`${API_URL}/alerts/mark-read`, { alert_ids: alertIds });
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/alerts/mark-read', { alert_ids: alertIds });
  } catch (error) {
    console.error('Error marking alerts as read:', error);
    throw error;
  }
};

// Get heatmap data
export const getHeatmapData = async () => {
  try {
    // In a real app, we would use this:
    // const response = await axios.get(`${API_URL}/heatmap`);
    // return response.data;
    
    // For demo purposes, we'll simulate the API call
    return await simulateApiCall('/heatmap');
  } catch (error) {
    console.error('Error fetching heatmap data:', error);
    throw error;
  }
};