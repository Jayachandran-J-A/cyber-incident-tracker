import requests
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from flask import Flask, render_template
from datetime import datetime, timedelta, timezone
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import base64
from io import BytesIO

app = Flask(__name__)

# Database initialization (unchanged)
def init_db():
    conn = sqlite3.connect('cyber_incidents.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id TEXT PRIMARY KEY, 
                  description TEXT, 
                  published_date TEXT, 
                  last_modified_date TEXT, 
                  severity TEXT)''')
    conn.commit()
    conn.close()

# Updated function to fetch data from NVD
def fetch_nvd_data():
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=30)
    
    # Format dates for the API request
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC+00:00")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {
        "pubStartDate": start_date_str,
        "pubEndDate": end_date_str,
        "resultsPerPage": 2000  # Adjust as needed
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()['vulnerabilities']
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return []

# Process and store incidents (unchanged)
def process_and_store_incidents(incidents):
    conn = sqlite3.connect('cyber_incidents.db')
    c = conn.cursor()
    for incident in incidents:
        cve = incident['cve']
        description = cve['descriptions'][0]['value'].lower()
        if 'india' in description or 'indian' in description:
            c.execute('''INSERT OR REPLACE INTO incidents 
                         (id, description, published_date, last_modified_date, severity) 
                         VALUES (?, ?, ?, ?, ?)''',
                      (cve['id'], 
                       description, 
                       cve['published'],
                       cve['lastModified'],
                       cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')))
    conn.commit()
    conn.close()

# Get data as a pandas DataFrame (unchanged)
def get_incidents_df():
    conn = sqlite3.connect('cyber_incidents.db')
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    df['published_date'] = pd.to_datetime(df['published_date'])
    return df

# Create severity distribution chart (unchanged)
def create_severity_chart(df):
    severity_counts = df['severity'].value_counts()
    fig = px.pie(values=severity_counts.values, names=severity_counts.index, title='Incident Severity Distribution')
    return fig.to_json()

# Create incidents over time chart (unchanged)
def create_time_chart(df):
    df['date'] = df['published_date'].dt.date
    daily_counts = df.groupby('date').size().reset_index(name='count')
    fig = px.bar(daily_counts, x='date', y='count', title='Incidents Over Time')
    return fig.to_json()

# Create word cloud (unchanged)
def create_word_cloud(df):
    text = ' '.join(df['description'])
    wordcloud = WordCloud(width=800, height=400, background_color='white').generate(text)
    
    plt.figure(figsize=(10, 5))
    plt.imshow(wordcloud, interpolation='bilinear')
    plt.axis('off')
    
    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()

@app.route('/')
def index():
    df = get_incidents_df()
    severity_chart = create_severity_chart(df)
    time_chart = create_time_chart(df)
    word_cloud = create_word_cloud(df)
    
    return render_template('index.html', 
                           incidents=df.to_dict('records'),
                           severity_chart=severity_chart,
                           time_chart=time_chart,
                           word_cloud=word_cloud)

if __name__ == '__main__':
    init_db()
    incidents = fetch_nvd_data()
    process_and_store_incidents(incidents)
    app.run(debug=True)