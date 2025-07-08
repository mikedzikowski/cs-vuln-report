# cs-vuln-report

# CrowdStrike Container Vulnerability Analyzer

A comprehensive Python script that fetches all container vulnerabilities from CrowdStrike Falcon and aggregates image counts for each CVE, providing detailed vulnerability analysis and reporting.

## 🚀 Features

- **Complete Data Extraction**: Fetches ALL vulnerabilities from your CrowdStrike environment (not just the first 100)
- **CVE Image Mapping**: Gets exact image counts affected by each CVE using CrowdStrike's aggregation API
- **Registry Filtering**: Support for including/excluding specific container registries
- **Comprehensive Reporting**: Detailed JSON output with vulnerability metadata, impact analysis, and statistics
- **Error Handling**: Robust retry logic and graceful handling of API limits
- **Progress Tracking**: Real-time progress indicators for large datasets

## 📋 Prerequisites

- Python 3.6+
- CrowdStrike Falcon API credentials with **Container Security: Read** permissions
- `requests` library

## 🔧 Installation

1. **Clone or download the script**
```bash
wget https://your-script-location/crowdstrike_vuln_analyzer.py
# or copy the script content to a local file
```

2. **Install dependencies**
```bash
pip install requests
```

3. **Get CrowdStrike API Credentials**
   - Log into CrowdStrike Falcon Console
   - Go to **Support** → **API Clients & Keys**
   - Create a new API client with **Container Security: Read** scope
   - Note your Client ID and Client Secret

## ⚙️ Configuration

Edit the script and update these values in the `main()` function:

```python
# Your CrowdStrike API Configuration
BASE_URL = "https://api.crowdstrike.com"  # Update for your cloud
CLIENT_ID = "your_client_id_here"
CLIENT_SECRET = "your_client_secret_here"
```

### CrowdStrike Cloud URLs
- **US-1**: `https://api.crowdstrike.com`
- **US-2**: `https://api.us-2.crowdstrike.com`
- **EU-1**: `https://api.eu-1.crowdstrike.com`
- **US-GOV-1**: `https://api.laggar.gcw.crowdstrike.com`

## 🏃‍♂️ Usage

### Basic Usage (All Vulnerabilities)
```bash
python3 crowdstrike_vuln_analyzer.py
```

### Advanced Configuration Options

#### Registry Filtering
```python
# Include only specific registries
INCLUDE_REGISTRIES = [
    "your-company.registry.com",
    "private.registry.internal"
]

# Include all registries (default)
INCLUDE_REGISTRIES = None
```

#### Vulnerability Filtering
```python
# Only high and critical vulnerabilities
VULN_FILTERS = "severity:['High','Critical']"

# Only vulnerabilities with CVSS >= 7.0
VULN_FILTERS = "cvss_score:>=7.0"

# Only exploitable vulnerabilities
VULN_FILTERS = "exploit_found:true"

# All vulnerabilities (default)
VULN_FILTERS = None
```

## 📊 Output

### Console Output
The script provides real-time progress and summary statistics:

```
🚀 CROWDSTRIKE COMPLETE VULNERABILITY SCAN - TRULY FIXED
================================================================================

--- BATCH 1 ---
Offset: 0, Limit: 100
✅ API Response: 100 vulnerabilities
🎯 API reports 9503 total vulnerabilities available
📈 Total collected: 100

...

✅ COLLECTED 9,503 TOTAL VULNERABILITIES
🔍 Extracting unique CVE IDs...
✅ FOUND 2,847 UNIQUE CVE IDs

🔄 PROCESSING ALL 2,847 CVEs FOR IMAGE COUNTS
📊 Progress: 1/2847 CVEs (0.0%)
📊 Progress: 100/2847 CVEs (3.5%)
...

🎉 TRULY FIXED ANALYSIS RESULTS 🎉
⏱️  Runtime: 45m 23s
💾 Results saved to: vulnerability_analysis_TRULY_FIXED_20250107_173743.json
🔍 Total CVEs processed: 2,847

📊 AGGREGATION SUMMARY:
   ✅ Successful: 2,840
   ❌ Failed: 7
   📈 Success rate: 99.8%
   🖼️  Total images affected: 125,432

🎯 IMPACT DISTRIBUTION:
   🔴 Critical (>500 images): 23
   🟠 High (101-500 images): 156
   🟡 Medium (11-100 images): 445
   🟢 Low (1-10 images): 892
   ⚪ None (0 images): 1,331

🏆 TOP 30 CVEs BY IMAGE COUNT:
 1. CVE-2025-0395: 930 images 🟠 High (CVSS: 7.5) ✅
 2. CVE-2023-0465: 921 images 🟡 Medium (CVSS: 5.3) ✅
 3. CVE-2017-11164: 579 images 🟠 High (CVSS: 7.5) ✅
...
```

### JSON Output
Detailed results are saved to a timestamped JSON file:

```json
[
  {
    "cve_id": "CVE-2025-0395",
    "image_count": 930,
    "severity": "High",
    "cvss_score": 7.5,
    "cps_current_rating": "Low",
    "description": "HTTP/2 protocol vulnerability that could allow...",
    "published_date": "2025-01-15T10:30:00Z",
    "images_impacted": 930,
    "packages_impacted": 71,
    "containers_impacted": 580,
    "remediation_available": true,
    "exploit_found": false,
    "aggregation_success": true,
    "error": null
  }
]
```

## 📈 Data Analysis

### Using Python
```python
import json
import pandas as pd

# Load results
with open('vulnerability_analysis_TRULY_FIXED_20250107_173743.json', 'r') as f:
    results = json.load(f)

# Convert to DataFrame for analysis
df = pd.DataFrame(results)

# Find high-impact vulnerabilities
high_impact = df[df['image_count'] > 100]
print(f"High impact CVEs: {len(high_impact)}")

# Severity distribution
print(df['severity'].value_counts())

# Export to CSV for Excel
df.to_csv('vulnerability_analysis.csv', index=False)
```

### Key Metrics
- **Total CVEs**: Number of unique vulnerabilities found
- **Image Count**: Exact number of container images affected per CVE
- **Impact Distribution**: Categorization by number of affected images
- **Success Rate**: Percentage of successful API aggregations
- **Coverage**: Percentage of available data collected

## 🔍 JSON Schema

Each CVE entry contains:

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier |
| `image_count` | integer | Number of affected container images |
| `severity` | string | Vulnerability severity (Critical/High/Medium/Low) |
| `cvss_score` | float | CVSS base score (0-10) |
| `cps_current_rating` | string | CrowdStrike's current risk rating |
| `description` | string | Detailed vulnerability description |
| `published_date` | string | CVE publication date (ISO format) |
| `images_impacted` | integer | Images affected (from vulnerability data) |
| `packages_impacted` | integer | Number of affected packages |
| `containers_impacted` | integer | Number of affected containers |
| `remediation_available` | boolean | Whether remediation is available |
| `exploit_found` | boolean | Whether exploits are known |
| `aggregation_success` | boolean | Whether image count aggregation succeeded |
| `error` | string/null | Error message if aggregation failed |

## 🛠️ Troubleshooting

### Common Issues

#### Authentication Errors
```
✗ Authentication failed: 401 Client Error: Unauthorized
```
**Solution**: Verify your Client ID and Client Secret are correct and have Container Security: Read permissions.

#### API Rate Limiting
```
❌ Error in batch X: 429 Too Many Requests
```
**Solution**: The script includes retry logic. If persistent, contact CrowdStrike support about rate limits.

#### Incomplete Data Collection
```
📊 Coverage: 85.2%
```
**Solution**: This is normal due to API pagination limits. The script collects as much data as possible.

### Performance Optimization

- **Large Environments**: For 10,000+ vulnerabilities, expect 30-60 minute runtime
- **Registry Filtering**: Use `INCLUDE_REGISTRIES` instead of processing all registries for better performance
- **Vulnerability Filtering**: Use `VULN_FILTERS` to focus on specific severity levels

## 📝 API Endpoints Used

1. **OAuth2 Token**: `/oauth2/token`
2. **Vulnerabilities**: `/container-security/combined/vulnerabilities/v1`
3. **Image Aggregation**: `/container-security/aggregates/images/count/v1`

## 🔒 Security Notes

- Store API credentials securely (consider environment variables)
- The script only requires read permissions
- All API calls use HTTPS
- No sensitive data is logged or stored

## 📄 License

This script is provided as-is for CrowdStrike customers. Modify and distribute according to your organization's policies.

## 🤝 Support

For issues related to:
- **CrowdStrike APIs**: Contact CrowdStrike Support
- **Script functionality**: Check the troubleshooting section above
- **Custom modifications**: Consult your development team

## 🔄 Version History

- **v1.0**: Initial release with basic vulnerability fetching
- **v2.0**: Added proper pagination and error handling
- **v3.0**: Fixed API limits and added comprehensive reporting
- **v4.0**: Enhanced registry filtering and retry logic

---

**⚠️ Important**: This script processes ALL vulnerabilities in your environment. For large deployments, expect significant runtime and ensure adequate system resources.
