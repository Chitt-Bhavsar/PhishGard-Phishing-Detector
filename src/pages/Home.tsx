import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, Loader2, Shield, ExternalLink } from 'lucide-react';
import { analyzeUrl } from '../services/api';
import { useSocket } from '../context/SocketContext';

const Home = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [analysisStatus, setAnalysisStatus] = useState('');
  const { socket } = useSocket();

  useEffect(() => {
    if (!socket) return;

    // Listen for analysis updates
    socket.on('analysis_update', (data) => {
      if (data.url === url) {
        setAnalysisStatus(data.message);
      }
    });

    // Listen for analysis completion
    socket.on('analysis_complete', (data) => {
      if (data.url === url) {
        setResult(data);
        setLoading(false);
        setAnalysisStatus('');
      }
    });

    // Listen for analysis errors
    socket.on('analysis_error', (data) => {
      if (data.url === url) {
        setError(`Analysis failed: ${data.error}`);
        setLoading(false);
        setAnalysisStatus('');
      }
    });

    return () => {
      socket.off('analysis_update');
      socket.off('analysis_complete');
      socket.off('analysis_error');
    };
  }, [socket, url]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url) {
      setError('Please enter a URL');
      return;
    }
    
    // Add http:// prefix if missing
    let processedUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      processedUrl = 'http://' + url;
      setUrl(processedUrl);
    }
    
    try {
      setLoading(true);
      setError('');
      setResult(null);
      setAnalysisStatus('Starting analysis...');
      
      await analyzeUrl(processedUrl);
      
      // The actual result will be received via WebSocket
    } catch (err) {
      setError('Failed to analyze URL. Please try again.');
      setLoading(false);
      console.error(err);
    }
  };

  return (
    <div className="container mx-auto px-4 py-12">
      <div className="max-w-3xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-800 mb-4">Advanced Phishing URL Detection</h1>
          <p className="text-lg text-gray-600">
            Enter a URL below to check if it's legitimate or potentially malicious.
          </p>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg p-8 mb-8">
          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <label htmlFor="url" className="block text-gray-700 font-medium mb-2">
                URL to Check
              </label>
              <input
                type="text"
                id="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              />
              {error && <p className="mt-2 text-red-600 text-sm">{error}</p>}
            </div>
            
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-indigo-600 text-white py-3 px-6 rounded-lg hover:bg-indigo-700 transition-colors disabled:bg-indigo-400 flex items-center justify-center"
            >
              {loading ? (
                <>
                  <Loader2 className="animate-spin mr-2 h-5 w-5" />
                  {analysisStatus || 'Analyzing...'}
                </>
              ) : (
                'Analyze URL'
              )}
            </button>
          </form>
        </div>
        
        {loading && !result && (
          <div className="bg-white rounded-lg shadow-lg p-8 mb-8">
            <div className="flex flex-col items-center">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500 mb-4"></div>
              <p className="text-gray-600">{analysisStatus || 'Analyzing URL...'}</p>
            </div>
          </div>
        )}
        
        {result && (
          <div className={`bg-white rounded-lg shadow-lg p-8 ${
            result.is_phishing ? 'border-l-4 border-red-500' : 'border-l-4 border-green-500'
          }`}>
            <div className="flex items-start mb-4">
              {result.is_phishing ? (
                <AlertTriangle className="h-8 w-8 text-red-500 mr-3 flex-shrink-0" />
              ) : (
                <CheckCircle className="h-8 w-8 text-green-500 mr-3 flex-shrink-0" />
              )}
              <div>
                <h2 className="text-2xl font-bold">
                  {result.is_phishing ? 'Potential Phishing Detected' : 'URL Appears Safe'}
                </h2>
                <p className="text-gray-600 mt-1">
                  {result.url}
                </p>
              </div>
            </div>
            
            <div className="mb-6">
              <div className="bg-gray-100 rounded-lg p-4">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-medium">Confidence Score</span>
                  <span className={`font-bold ${
                    result.confidence_score > 75 ? 'text-red-600' : 
                    result.confidence_score > 50 ? 'text-yellow-600' : 
                    'text-green-600'
                  }`}>
                    {result.confidence_score}%
                  </span>
                </div>
                <div className="w-full bg-gray-300 rounded-full h-2.5">
                  <div 
                    className={`h-2.5 rounded-full ${
                      result.confidence_score > 75 ? 'bg-red-600' : 
                      result.confidence_score > 50 ? 'bg-yellow-600' : 
                      'bg-green-600'
                    }`}
                    style={{ width: `${result.confidence_score}%` }}
                  ></div>
                </div>
              </div>
            </div>
            
            {/* Threat Intelligence Results */}
            {result.threat_intel_results && result.threat_intel_results.length > 0 && (
              <div className="mb-6">
                <h3 className="font-semibold text-lg mb-3">Threat Intelligence</h3>
                <div className="bg-gray-100 rounded-lg p-4">
                  {result.threat_intel_results.map((intel: any, index: number) => (
                    <div key={index} className="mb-2 last:mb-0">
                      <div className="flex items-start">
                        <span className={`inline-block w-3 h-3 rounded-full mr-2 mt-1.5 ${
                          intel.is_malicious ? 'bg-red-500' : 'bg-green-500'
                        }`}></span>
                        <div>
                          <span className="font-medium">{intel.source}: </span>
                          <span>{intel.details}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Analysis Details */}
            <div className="mb-6">
              <h3 className="font-semibold text-lg mb-3">Analysis Details</h3>
              <ul className="space-y-2 bg-gray-100 rounded-lg p-4">
                {result.analysis_details.map((detail: any, index: number) => (
                  <li key={index} className="flex items-start">
                    <span className={`inline-block w-3 h-3 rounded-full mr-2 mt-1.5 ${
                      detail.risk_level === 'high' ? 'bg-red-500' :
                      detail.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                    }`}></span>
                    <span>{detail.description}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            {/* Domain Information */}
            {result.whois_data && (
              <div className="mb-6">
                <h3 className="font-semibold text-lg mb-3">Domain Information</h3>
                <div className="bg-gray-100 rounded-lg p-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm">
                        <span className="font-medium">Registrar: </span>
                        {result.whois_data.registrar || 'Unknown'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Creation Date: </span>
                        {result.whois_data.creation_date || 'Unknown'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Expiration Date: </span>
                        {result.whois_data.expiration_date || 'Unknown'}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm">
                        <span className="font-medium">Domain Age: </span>
                        {result.whois_data.domain_age_days ? `${result.whois_data.domain_age_days} days` : 'Unknown'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Registrant: </span>
                        {result.whois_data.registrant || 'Unknown'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Country: </span>
                        {result.whois_data.registrant_country || 'Unknown'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {/* SSL Certificate Information */}
            {result.ssl_info && (
              <div className="mb-6">
                <h3 className="font-semibold text-lg mb-3">SSL Certificate</h3>
                <div className="bg-gray-100 rounded-lg p-4">
                  {result.ssl_info.has_ssl ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm">
                          <span className="font-medium">Issuer: </span>
                          {result.ssl_info.issuer || 'Unknown'}
                        </p>
                        <p className="text-sm">
                          <span className="font-medium">Valid From: </span>
                          {result.ssl_info.valid_from || 'Unknown'}
                        </p>
                        <p className="text-sm">
                          <span className="font-medium">Valid Until: </span>
                          {result.ssl_info.valid_until || 'Unknown'}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm">
                          <span className="font-medium">Self-Signed: </span>
                          {result.ssl_info.is_self_signed ? 'Yes' : 'No'}
                        </p>
                        <p className="text-sm">
                          <span className="font-medium">Expired: </span>
                          {result.ssl_info.is_expired ? 'Yes' : 'No'}
                        </p>
                        <p className="text-sm">
                          <span className="font-medium">Short-Lived: </span>
                          {result.ssl_info.is_short_lived ? 'Yes' : 'No'}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-sm">This website does not use SSL encryption.</p>
                  )}
                </div>
              </div>
            )}
            
            {/* Webpage Content Analysis */}
            {result.content_analysis && !result.content_analysis.error && (
              <div>
                <h3 className="font-semibold text-lg mb-3">Webpage Content Analysis</h3>
                <div className="bg-gray-100 rounded-lg p-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm">
                        <span className="font-medium">Page Title: </span>
                        {result.content_analysis.page_title || 'None'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Login Form: </span>
                        {result.content_analysis.has_login_form ? 'Detected' : 'Not detected'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Password Fields: </span>
                        {result.content_analysis.password_input_count || 0}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm">
                        <span className="font-medium">Suspicious Scripts: </span>
                        {result.content_analysis.has_suspicious_scripts ? 'Detected' : 'Not detected'}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">External Resources: </span>
                        {result.content_analysis.external_resource_count || 0}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Security Keywords: </span>
                        {result.content_analysis.security_keyword_count || 0}
                      </p>
                    </div>
                  </div>
                  
                  {result.content_analysis.brand_mentions && result.content_analysis.brand_mentions.length > 0 && (
                    <div className="mt-3">
                      <p className="text-sm font-medium">Brand Mentions:</p>
                      <div className="flex flex-wrap gap-2 mt-1">
                        {result.content_analysis.brand_mentions.map((brand: string, index: number) => (
                          <span key={index} className="px-2 py-1 bg-gray-200 rounded-full text-xs">
                            {brand}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
            
            {/* Recommendations */}
            <div className="mt-8 p-4 bg-indigo-50 rounded-lg border border-indigo-100">
              <h3 className="font-semibold text-lg mb-2 text-indigo-800">Recommendations</h3>
              <ul className="space-y-2">
                {result.is_phishing ? (
                  <>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>Do not visit this website or enter any personal information.</span>
                    </li>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>If you've already entered credentials, change your passwords immediately.</span>
                    </li>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>Consider reporting this URL to <a href="https://safebrowsing.google.com/safebrowsing/report_phish/" target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline inline-flex items-center">Google Safe Browsing <ExternalLink className="h-3 w-3 ml-1" /></a>.</span>
                    </li>
                  </>
                ) : (
                  <>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>This URL appears to be safe, but always remain vigilant online.</span>
                    </li>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>Verify that you're on the correct website before entering sensitive information.</span>
                    </li>
                    <li className="flex items-start">
                      <Shield className="h-5 w-5 text-indigo-600 mr-2 flex-shrink-0" />
                      <span>Look for HTTPS and a valid SSL certificate before making transactions.</span>
                    </li>
                  </>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Home;