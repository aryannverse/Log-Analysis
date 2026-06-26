<div align="center">

# Log Analysis and Live Anomaly Triage Hub

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-Charts-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Qwen%203.6-F55F45?style=for-the-badge)

</div>

An interactive, high-performance log analysis dashboard and real-time anomaly triage pipeline powered by Groq's Qwen 3.6 API.

---

## About The Project

This platform processes raw log files from massive cloud infrastructure datasets and feeds security and exception events directly into a locally run LLM coprocessor. 

Unlike traditional batch parsers, the application features:
- **Dynamic Format Analyzer**: Analyzes any uploaded dataset sample via Groq's Qwen 3.6 API to dynamically extract the format type, regex schema, and custom security/anomaly keyword lists.
- **Memory-Efficient Chunk Parsing**: Streams logs line-by-line using file seeking to handle large-scale datasets (up to 500 MB upload limit) without causing memory exhaustion.
- **Cloud LLM Coprocessor**: Sends raw log messages to Groq's Qwen 3.6 API for explainability and remediation instructions.
- **Filtered Triage Feed**: Displays only security anomalies one by one, allowing operators to analyze vulnerabilities sequentially.

---

## Key Features

- **Dynamic File Uploader**: Drag and drop any `.log`, `.txt`, `.csv`, or `.pdf` file up to 500 MB.
- **Automated Regex Parsing**: Leverages LLM format extraction to generate matching Python regex patterns and parse custom logs dynamically.
- **Analytics Dashboard**: Renders distribution donut charts, component frequencies, and log level time-series using Plotly.
- **Groq API Integration**: Connects to the Groq REST API using native JSON mode to guarantee structured explanations.
- **Clean Aesthetic**: Modern dark mode UI using Outfit typography, custom Streamlit styling, and standard tables.

---

## How It Works

1. **Log Sample Extraction**: When a file is uploaded, the app extracts a small sample and sends it to the Groq Qwen 3.6 API.
2. **Schema Determination**: The API returns a JSON configuration containing a Python regex pattern with named groups (`level`, `message`, `timestamp`, `component`), along with tailored anomaly/security keywords.
3. **Chunked Parsing**: The application parses the remaining log file using the generated regex, falling back to raw message parsing if a line doesn't match the regex.
4. **Vulnerability Triage**: The Live Triage stream filters the parsed logs to show only the security anomalies detected based on the custom security keywords.


---

## Tech Stack

### Processing & Core Logic
- `Pandas`
- `Requests`
- `Groq API` (via native REST requests)
- `Python-dateutil`

### Dashboard & Visualizations
- `Streamlit`
- `Plotly Express`

---

## Project Structure

```bash
Log-Analysis/
├── components/
│   ├── dashboard.py     # Plotly analytics visualization grids
│   └── triage.py        # Live log triage panel and status handlers
├── app.py               # Main application routing and sidebar controller
├── data_loader.py       # Regex log layout parsers and Groq API connector
├── config.py            # Local default regexes and anomaly configurations
├── Dockerfile           # Multi-stage lightweight docker configuration
├── .dockerignore        # Exclusions for docker build context
├── requirements.txt     # Python application dependency declarations
├── .gitignore           # Git ignore declarations
└── README.md            # Technical documentation
```

---

## Architecture

![Architecture](Images/mermaid-diagram-2026-06-21-163737%201.png)

---

## Local Setup & Deployment

### 1) Configure API Key
Create a `.env` file in the root directory:
```bash
cp .env.example .env
```
Open `.env` and set your `GROQ_API_KEY` obtained from the [Groq Console](https://console.groq.com/).

### Option A: Running with Docker (Recommended)
You can build and run the entire application cleanly using Docker:

1. **Build the Docker Image**:
   ```bash
   docker build -t log-analysis-app .
   ```
2. **Run the Docker Container**:
   ```bash
   docker run -p 8501:8501 --env-file .env --name log-analysis-app log-analysis-app
   ```
3. **Access the Application**:
   Open **`http://localhost:8501`** in your browser.

### Option B: Local Manual Setup

1. **Clone and Prepare Environment**:
   ```bash
   git clone https://gitlab.com/aryannverse/log-analysis-application.git
   cd log-analysis-application
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run the Streamlit Application**:
   ```bash
   streamlit run app.py
   ```
   Open **`http://localhost:8501`** in your browser.

---

<div align="center">
Built with focus, curiosity, and obsession by <a href="https://gitlab.com/aryannverse">aryannverse</a>
</div>
