import React from 'react';
import { Shield, AlertTriangle, Database, Server } from 'lucide-react';

const About = () => {
  return (
    <div className="container mx-auto px-4 py-12">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-800 mb-4">About PhishGuard</h1>
          <p className="text-lg text-gray-600">
            Protecting users from phishing attacks with advanced detection technology
          </p>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg p-8 mb-12">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">Our Mission</h2>
          <p className="text-gray-600 mb-6">
            PhishGuard was created with a simple mission: to make the internet safer by helping users identify and avoid phishing websites. 
            Phishing attacks remain one of the most common and effective cyber threats, with millions of people falling victim each year.
          </p>
          <p className="text-gray-600">
            Our platform uses advanced machine learning algorithms and threat intelligence to analyze URLs and determine if they're legitimate or potentially malicious. 
            We're committed to providing this service to help individuals and organizations protect themselves from online threats.
          </p>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg p-8 mb-12">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">How It Works</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="flex flex-col items-center text-center">
              <div className="bg-indigo-100 p-4 rounded-full mb-4">
                <AlertTriangle className="h-10 w-10 text-indigo-600" />
              </div>
              <h3 className="text-xl font-semibold mb-2">URL Analysis</h3>
              <p className="text-gray-600">
                Our system examines various aspects of a URL including its domain age, SSL certificate, redirects, and similarity to known legitimate domains.
              </p>
            </div>
            
            <div className="flex flex-col items-center text-center">
              <div className="bg-indigo-100 p-4 rounded-full mb-4">
                <Database className="h-10 w-10 text-indigo-600" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Machine Learning</h3>
              <p className="text-gray-600">
                We use sophisticated machine learning models trained on millions of URLs to identify patterns and characteristics common to phishing websites.
              </p>
            </div>
            
            <div className="flex flex-col items-center text-center">
              <div className="bg-indigo-100 p-4 rounded-full mb-4">
                <Server className="h-10 w-10 text-indigo-600" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Threat Intelligence</h3>
              <p className="text-gray-600">
                Our system cross-references URLs with multiple threat intelligence databases to check if a domain has been previously reported as malicious.
              </p>
            </div>
            
            <div className="flex flex-col items-center text-center">
              <div className="bg-indigo-100 p-4 rounded-full mb-4">
                <Shield className="h-10 w-10 text-indigo-600" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Real-time Protection</h3>
              <p className="text-gray-600">
                Get instant results about the safety of any URL before you visit it, helping you make informed decisions about which websites to trust.
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg p-8">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">Technology Stack</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-xl font-semibold mb-3">Frontend</h3>
              <ul className="space-y-2 text-gray-600">
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  React for interactive UI components
                </li>
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  Tailwind CSS for responsive design
                </li>
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  Chart.js for data visualization
                </li>
              </ul>
            </div>
            
            <div>
              <h3 className="text-xl font-semibold mb-3">Backend</h3>
              <ul className="space-y-2 text-gray-600">
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  Flask Python framework
                </li>
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  SQLite for data storage
                </li>
                <li className="flex items-center">
                  <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                  Scikit-learn for machine learning models
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;