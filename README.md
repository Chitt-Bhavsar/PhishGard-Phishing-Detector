# PhishGuard - Phishing URL Detection Application

PhishGuard is a full-stack web application that helps users detect potentially malicious or phishing URLs. The application provides a simple interface for users to input URLs and receive an analysis of whether the URL is safe or potentially dangerous.

## Features

- URL analysis to detect phishing attempts
- Confidence score for each analysis
- Detailed explanation of why a URL is classified as phishing or safe
- Dashboard with statistics and visualizations of past detections
- Recent scans history

## Tech Stack

### Frontend
- React
- TypeScript
- Tailwind CSS
- Chart.js for data visualization
- Lucide React for icons

### Backend
- Flask (Python)
- SQLite for database
- Scikit-learn for machine learning features

## Getting Started

### Prerequisites
- Node.js (v14 or higher)
- Python (v3.8 or higher)
- npm or yarn

### Installation

1. Clone the repository

2. Install frontend dependencies
```
npm install
```

3. Install backend dependencies
```
cd backend
pip install -r requirements.txt
```

### Running the Application

1. Start the backend server
```
cd backend
python app.py
```

2. Start the frontend development server
```
npm run dev
```

3. Open your browser and navigate to the URL shown in your terminal (typically http://localhost:5173)

## How It Works

1. Users enter a URL in the input field on the home page
2. The application sends the URL to the backend for analysis
3. The backend extracts features from the URL and analyzes them using a combination of rule-based checks and machine learning
4. The analysis results are returned to the frontend and displayed to the user
5. The results include a confidence score and detailed explanations of the factors that contributed to the classification
6. All scans are stored in the database for historical analysis and visualization in the dashboard

## Dashboard

The dashboard provides visualizations and statistics about the URLs that have been scanned, including:

- Total number of URLs scanned
- Number of phishing URLs detected
- Number of safe URLs
- Charts showing the distribution of safe vs. phishing URLs
- Recent scan history
