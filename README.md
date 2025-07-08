# CrowdStrike Container Vulnerability Analyzer

A comprehensive Python script that fetches all container vulnerabilities from CrowdStrike Falcon and aggregates image counts for each CVE, providing detailed vulnerability analysis and reporting with **working registry filtering**.

## 🚀 Features

- **Complete Data Extraction**: Fetches ALL vulnerabilities from your CrowdStrike environment (not just the first 100)
- **CVE Image Mapping**: Gets exact image counts affected by each CVE using CrowdStrike's aggregation API
- **✅ Working Registry Filtering**: Include/exclude specific container registries with verified functionality
- **Registry Discovery**: Automatically discovers all active registries in your environment
- **Comprehensive Reporting**: Detailed JSON output with vulnerability metadata, registry breakdowns, and impact analysis
- **Error Handling**: Robust retry logic and graceful handling of API limits
- **Progress Tracking**: Real-time progress indicators for large datasets
- **Scalable Architecture**: Handles environments from small (1K vulnerabilities) to mega enterprise (100K+ vulnerabilities)

## 📋 Prerequisites

- Python 3.6+
- CrowdStrike Falcon API credentials with **Container Security: Read** permissions
- `requests` library

## 🔧 Installation

1. **Clone or download the script**
```bash
curl -sSL -o crowdstrike_vuln_analyzer.py https://raw.githubusercontent.com/mikedzikowski/cs-vuln-report/refs/heads/main/crowdstrike_vuln_analyzer.py
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

### Basic Usage (All Vulnerabilities, All Registries)
```bash
python3 crowdstrike_vuln_analyzer.py
```

### Registry Filtering Options

#### Option 1: Include Only Specific Registries ✅ **RECOMMENDED**
```python
INCLUDE_REGISTRIES = [
    "registry-1.docker.io",  # Docker Hub
    "gcr.io",                # Google Container Registry
    "quay.io",               # Red Hat Quay
    "your-company.registry.com"  # Your private registry
]
EXCLUDE_REGISTRIES = None
```

#### Option 2: Exclude Specific Registries
```python
INCLUDE_REGISTRIES = None
EXCLUDE_REGISTRIES = [
    "mcr.microsoft.com",     # Microsoft Container Registry
    "public.ecr.aws",        # AWS Public ECR
    "registry.redhat.io"     # Red Hat Registry
]
```

#### Option 3: All Registries (Default)
```python
INCLUDE_REGISTRIES = None
EXCLUDE_REGISTRIES = None
```

### Vulnerability Filtering Options

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

### Environment Size Handling

The script automatically detects and handles different environment sizes:

- **Small** (< 1K vulnerabilities): ~5-10 minutes
- **Medium** (1K-10K vulnerabilities): ~10-30 minutes  
- **Large** (10K-50K vulnerabilities): ~30-120 minutes
- **Enterprise** (50K-100K vulnerabilities): ~2-4 hours
- **Mega Enterprise** (100K+ vulnerabilities): Requires filtering

## 📊 Output

### Console Output
The script provides real-time progress and comprehensive statistics:

```
🚀 CROWDSTRIKE VULNERABILITY ANALYZER - REGISTRY FILTERING WORKS!
================================================================================

🔍 Registry Discovery (optional):
Testing 17 common registries with 5 CVEs...
  ✅ Found active registry: registry-1.docker.io
  ✅ Found active registry: gcr.io
  ✅ Found active registry: quay.io
  ✅ Found active registry: mcr.microsoft.com

✅ Discovery complete! Found 4 active registries

📊 Including only registries: ['registry-1.docker.io', 'gcr.io', 'quay.io']

Batch 1: offset=0, limit=100
🎯 Total vulnerabilities available: 9,503
✅ Added 100 vulnerabilities (total: 100)
...

✅ Collected 9,503 vulnerabilities
✅ Found 2,847 unique CVE IDs

🔄 Processing 2,847 CVEs for image counts...
📊 Progress: 1/2,847 (0.0%)
📊 Progress: 100/2,847 (3.5%)
...

🎉 ANALYSIS COMPLETE - REGISTRY FILTERING WORKING! 🎉
⏱️  Runtime: 45m 23s
💾 Results saved to: vulnerability_analysis_INCLUDE_REGISTRIES_20250107_173743.json
🔍 Total CVEs processed: 2,847

📊 SUMMARY:
   ✅ Successful: 2,840
   🖼️  Total images: 45,231

🏆 TOP 20 CVEs BY IMAGE COUNT:
 1. CVE-2025-0395: 1,245 images 🟠 High (CVSS: 7.5)
    Registry breakdown: registry-1.docker.io:856, gcr.io:234, quay.io:155
 2. CVE-2023-0465: 1,089 images 🟡 Medium (CVSS: 5.3)
    Registry breakdown: registry-1.docker.io:1089
...
```

### JSON Output
Detailed results are saved to a timestamped JSON file with registry filtering information:

```json
[
  {
    "cve_id": "CVE-2025-0395",
    "image_count": 1245,
    "total_count": 2890,
    "excluded_count": null,
    "registry_breakdown": {
      "registry-1.docker.io": 856,
      "gcr.io": 234,
      "quay.io": 155
    },
    "filtering_method": "include_registries",
    "severity": "High",
    "cvss_score": 7.5,
    "cps_current_rating": "Low",
    "description": "HTTP/2 protocol vulnerability that could allow...",
    "published_date": "2025-01-15T10:30:00Z",
    "images_impacted": 2890,
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
with open('vulnerability_analysis_INCLUDE_REGISTRIES_20250107_173743.json', 'r') as f:
    results = json.load(f)

# Convert to DataFrame for analysis
df = pd.DataFrame(results)

# Analyze registry-filtered results
registry_filtered = df[df['filtering_method'] == 'include_registries']
print(f"Registry-filtered CVEs: {len(registry_filtered)}")

# Find high-impact vulnerabilities in your registries
high_impact = df[df['image_count'] > 100]
print(f"High impact CVEs in filtered registries: {len(high_impact)}")

# Registry breakdown analysis
for _, row in df.head(10).iterrows():
    if row['registry_breakdown']:
        print(f"{row['cve_id']}: {row['registry_breakdown']}")

# Export to CSV for Excel
df.to_csv('vulnerability_analysis_with_registries.csv', index=False)
```

### Registry-Specific Analysis
```python
# Analyze which registries have the most vulnerabilities
registry_totals = {}
for result in results:
    if result.get('registry_breakdown'):
        for registry, count in result['registry_breakdown'].items():
            if isinstance(count, int):
                registry_totals[registry] = registry_totals.get(registry, 0) + count

print("Images by registry:")
for registry, total in sorted(registry_totals.items(), key=lambda x: x[1], reverse=True):
    print(f"  {registry}: {total:,} images")
```

## 🔍 Registry Discovery

The script includes automatic registry discovery:

```python
# Discovered registries in your environment
available_registries = analyzer.discover_all_registries()
print(f"Found registries: {available_registries}")

# Common registries found in enterprise environments:
# - registry-1.docker.io (Docker Hub)
# - gcr.io (Google Container Registry)
# - quay.io (Red Hat Quay)
# - mcr.microsoft.com (Microsoft Container Registry)
# - public.ecr.aws (AWS Public ECR)
# - ghcr.io (GitHub Container Registry)
# - registry.gitlab.com (GitLab Container Registry)
```

## 🔒 JSON Schema

Each CVE entry contains enhanced registry information:

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | string | CVE identifier |
| `image_count` | integer | Number of affected images (after registry filtering) |
| `total_count` | integer | Total images before filtering (exclude method only) |
| `excluded_count` | integer | Number of excluded images (exclude method only) |
| `registry_breakdown` | object | Count per registry `{"registry": count}` |
| `filtering_method` | string | `include_registries`, `exclude_registries`, or `all_registries` |
| `severity` | string | Vulnerability severity (Critical/High/Medium/Low) |
| `cvss_score` | float | CVSS base score (0-10) |
| `cps_current_rating` | string | CrowdStrike's current risk rating |
| `description` | string | Detailed vulnerability description |
| `published_date` | string | CVE publication date (ISO format) |
| `images_impacted` | integer | Total images affected (from vulnerability data) |
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

#### Registry Filtering Not Working
```
❌ Registry filtering failed for all registries
```
**Solution**: 
1. Run the registry discovery first to see available registries
2. Use exact registry names from the discovery output
3. Check that registries actually contain vulnerable images

#### No Registries Found
```
❌ No registries found - cannot test filtering
```
**Solution**: Your environment might not have container images, or the API permissions might be insufficient.

#### Performance Issues
```
⚠️ Processing taking longer than expected
```
**Solution**: 
- Use `INCLUDE_REGISTRIES` to focus on specific registries
- Add `VULN_FILTERS` to reduce the dataset size
- Consider running during off-peak hours

### Registry Filtering Debug

If registry filtering isn't working, run the debug version:

```python
# Add this to test registry filtering
analyzer.test_registry_filtering_comprehensive()
```

## 📊 Performance Guidelines

### Small Environment (< 1K vulnerabilities)
```python
# Default settings work fine
INCLUDE_REGISTRIES = None
VULN_FILTERS = None
# Expected runtime: 5-10 minutes
```

### Medium Environment (1K-10K vulnerabilities)
```python
# Consider focusing on important registries
INCLUDE_REGISTRIES = ["your-prod-registry.com", "registry-1.docker.io"]
VULN_FILTERS = None
# Expected runtime: 10-30 minutes
```

### Large Environment (10K-50K vulnerabilities)
```python
# Recommended to use filtering
INCLUDE_REGISTRIES = ["your-critical-registry.com"]
VULN_FILTERS = "severity:['High','Critical']"
# Expected runtime: 30-120 minutes
```

### Enterprise Environment (50K+ vulnerabilities)
```python
# Aggressive filtering recommended
INCLUDE_REGISTRIES = ["production.registry.com"]
VULN_FILTERS = "severity:['Critical']+exploit_found:true"
# Expected runtime: 2-4 hours
```

## 📝 API Endpoints Used

1. **OAuth2 Token**: `/oauth2/token`
2. **Vulnerabilities**: `/container-security/combined/vulnerabilities/v1`
3. **Image Aggregation**: `/container-security/aggregates/images/count/v1` ✅ **Registry filtering works here**
4. **Detections** (discovery): `/container-security/combined/detections/v1`

## 🔒 Security Notes

- Store API credentials securely (consider environment variables)
- The script only requires read permissions
- All API calls use HTTPS
- No sensitive data is logged or stored
- Registry filtering happens server-side (secure)

## 🎯 Use Cases

### Security Team Prioritization
```python
# Focus on critical vulnerabilities in production registries
INCLUDE_REGISTRIES = ["prod.company.com", "staging.company.com"]
VULN_FILTERS = "severity:['Critical','High']"
```

### Compliance Reporting
```python
# Exclude public registries for internal compliance
EXCLUDE_REGISTRIES = ["docker.io", "registry-1.docker.io", "public.ecr.aws"]
VULN_FILTERS = None
```

### Development Team Focus
```python
# Include only development registries
INCLUDE_REGISTRIES = ["dev.company.com", "test.company.com"]
VULN_FILTERS = "remediation_available:true"
```

### Executive Dashboard
```python
# High-level overview of critical issues
INCLUDE_REGISTRIES = None  # All registries
VULN_FILTERS = "severity:['Critical']+exploit_found:true"
```

## 📄 License

This script is provided as-is for CrowdStrike customers. Modify and distribute according to your organization's policies.

## 🔄 Version History

- **v1.0**: Initial release with basic vulnerability fetching
- **v2.0**: Added proper pagination and error handling
- **v3.0**: Fixed API limits and added comprehensive reporting
- **v4.0**: Enhanced registry filtering and retry logic
- **v5.0**: ✅ **Working registry filtering with discovery and comprehensive testing**

---

**⚠️ Important**: This script processes ALL vulnerabilities in your environment. For large deployments, expect significant runtime and ensure adequate system resources. **Registry filtering is now fully functional and tested!** 🎉

**🎯 Pro Tip**: Always run registry discovery first to see what registries are available in your environment, then configure filtering accordingly for optimal results.
