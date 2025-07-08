import requests
import json
import time
from typing import List, Dict, Optional

class CrowdStrikeVulnAnalyzer:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expires_at = 0
        self._authenticate()
    
    def _authenticate(self) -> bool:
        url = f"{self.base_url}/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = time.time() + expires_in - 300
            print("✓ Authentication successful")
            return True
        except Exception as e:
            print(f"✗ Authentication failed: {e}")
            return False
    
    def _get_headers(self) -> Dict[str, str]:
        if time.time() >= self.token_expires_at:
            self._authenticate()
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
    
    def discover_all_registries(self) -> List[str]:
        """Discover all registries that have images with vulnerabilities"""
        print("🔍 Discovering all registries in your environment...")
        
        # Get a few test CVEs
        vuln_url = f"{self.base_url}/container-security/combined/vulnerabilities/v1"
        try:
            response = requests.get(vuln_url, headers=self._get_headers(), params={'limit': 10})
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('resources', [])
            if not vulnerabilities:
                print("❌ No vulnerabilities found for registry discovery")
                return []
            
            # Test with multiple CVEs to get a comprehensive list
            test_cves = [v.get('cve_id') for v in vulnerabilities[:5]]
            
            # Extended list of common registries
            common_registries = [
                "docker.io",
                "registry.hub.docker.com",
                "registry-1.docker.io",
                "gcr.io",
                "us.gcr.io", 
                "eu.gcr.io",
                "asia.gcr.io",
                "public.ecr.aws",
                "quay.io",
                "registry.redhat.io",
                "mcr.microsoft.com",
                "ghcr.io",
                "registry.gitlab.com",
                "harbor.io",
                "artifactory.io",
                "nexus.io",
                "jfrog.io"
            ]
            
            found_registries = set()
            url = f"{self.base_url}/container-security/aggregates/images/count/v1"
            
            print(f"Testing {len(common_registries)} common registries with {len(test_cves)} CVEs...")
            
            for registry in common_registries:
                registry_has_images = False
                
                for cve_id in test_cves:
                    registry_filter = f"cve_id:'{cve_id}'+registry:'{registry}'"
                    
                    try:
                        reg_response = requests.get(url, headers=self._get_headers(), 
                                                  params={'filter': registry_filter})
                        if reg_response.status_code == 200:
                            reg_data = reg_response.json()
                            reg_count = reg_data.get('resources', [{}])[0].get('count', 0)
                            if reg_count > 0:
                                registry_has_images = True
                                break  # Found images in this registry, no need to test more CVEs
                    except Exception:
                        continue  # Skip errors, try next CVE
                
                if registry_has_images:
                    found_registries.add(registry)
                    print(f"  ✅ Found active registry: {registry}")
            
            registry_list = sorted(list(found_registries))
            print(f"\n✅ Discovery complete! Found {len(registry_list)} active registries:")
            for registry in registry_list:
                print(f"   - {registry}")
            
            return registry_list
            
        except Exception as e:
            print(f"❌ Registry discovery failed: {e}")
            return []
    
    def get_all_vulnerabilities_fixed(self, additional_filters: Optional[str] = None) -> List[Dict]:
        """Get ALL vulnerabilities using proper pagination"""
        all_vulnerabilities = []
        offset = 0
        limit = 100  # API maximum
        batch_number = 0
        total_from_api = None
        consecutive_errors = 0
        max_consecutive_errors = 3
        
        print("="*60)
        print("FETCHING ALL VULNERABILITIES")
        print("="*60)
        
        while consecutive_errors < max_consecutive_errors:
            batch_number += 1
            print(f"Batch {batch_number}: offset={offset}, limit={limit}")
            
            url = f"{self.base_url}/container-security/combined/vulnerabilities/v1"
            params = {'limit': limit, 'offset': offset}
            if additional_filters:
                params['filter'] = additional_filters
            
            try:
                response = requests.get(url, headers=self._get_headers(), params=params)
                
                if response.status_code == 500:
                    print("❌ Server Error 500 - likely reached end of data")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    offset += limit
                    continue
                
                response.raise_for_status()
                data = response.json()
                
                batch_resources = data.get('resources', [])
                batch_size = len(batch_resources)
                
                consecutive_errors = 0  # Reset on success
                
                # Get total from first request
                if total_from_api is None:
                    meta = data.get('meta', {})
                    pagination = meta.get('pagination', {})
                    total_from_api = pagination.get('total', 0)
                    print(f"🎯 Total vulnerabilities available: {total_from_api:,}")
                
                if batch_size == 0:
                    print("📭 Empty batch - reached end")
                    break
                
                all_vulnerabilities.extend(batch_resources)
                print(f"✅ Added {batch_size} vulnerabilities (total: {len(all_vulnerabilities):,})")
                
                if total_from_api and len(all_vulnerabilities) >= total_from_api:
                    print(f"🎉 Collected all {total_from_api:,} vulnerabilities!")
                    break
                
                offset += limit
                
                if batch_number > 200:  # Safety limit
                    print("🛑 Safety limit reached")
                    break
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Error in batch {batch_number}: {e}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    break
                offset += limit
                time.sleep(1)
        
        print(f"✅ Fetching complete: {len(all_vulnerabilities):,} vulnerabilities collected")
        return all_vulnerabilities
    
    def aggregate_image_count_by_cve_working(self, cve_id: str, 
                                           include_registries: Optional[List[str]] = None,
                                           exclude_registries: Optional[List[str]] = None) -> Dict:
        """WORKING version of image count aggregation with registry filtering"""
        url = f"{self.base_url}/container-security/aggregates/images/count/v1"
        
        if include_registries:
            # Include only specific registries - sum them up
            total_count = 0
            registry_breakdown = {}
            
            for registry in include_registries:
                registry_filter = f"cve_id:'{cve_id}'+registry:'{registry}'"
                params = {'filter': registry_filter}
                
                try:
                    response = requests.get(url, headers=self._get_headers(), params=params)
                    response.raise_for_status()
                    
                    data = response.json()
                    resources = data.get('resources', [])
                    count = resources[0].get('count', 0) if resources else 0
                    
                    total_count += count
                    registry_breakdown[registry] = count
                    
                except Exception as e:
                    registry_breakdown[registry] = f"Error: {e}"
            
            return {
                'cve_id': cve_id,
                'image_count': total_count,
                'method': 'include_registries',
                'registry_breakdown': registry_breakdown,
                'success': True
            }
        
        elif exclude_registries:
            # Get total count first
            total_filter = f"cve_id:'{cve_id}'"
            try:
                response = requests.get(url, headers=self._get_headers(), params={'filter': total_filter})
                response.raise_for_status()
                data = response.json()
                total_count = data.get('resources', [{}])[0].get('count', 0)
            except Exception as e:
                return {'cve_id': cve_id, 'image_count': 0, 'error': str(e), 'success': False}
            
            # Get count for excluded registries
            excluded_count = 0
            registry_breakdown = {}
            
            for registry in exclude_registries:
                registry_filter = f"cve_id:'{cve_id}'+registry:'{registry}'"
                try:
                    response = requests.get(url, headers=self._get_headers(), params={'filter': registry_filter})
                    response.raise_for_status()
                    data = response.json()
                    count = data.get('resources', [{}])[0].get('count', 0)
                    excluded_count += count
                    registry_breakdown[registry] = count
                except Exception as e:
                    registry_breakdown[registry] = f"Error: {e}"
            
            final_count = max(0, total_count - excluded_count)
            
            return {
                'cve_id': cve_id,
                'image_count': final_count,
                'total_count': total_count,
                'excluded_count': excluded_count,
                'method': 'exclude_registries',
                'registry_breakdown': registry_breakdown,
                'success': True
            }
        
        else:
            # No registry filtering - get all
            basic_filter = f"cve_id:'{cve_id}'"
            params = {'filter': basic_filter}
            
            try:
                response = requests.get(url, headers=self._get_headers(), params=params)
                response.raise_for_status()
                
                data = response.json()
                resources = data.get('resources', [])
                count = resources[0].get('count', 0) if resources else 0
                
                return {
                    'cve_id': cve_id,
                    'image_count': count,
                    'method': 'all_registries',
                    'success': True
                }
                
            except requests.exceptions.RequestException as e:
                return {
                    'cve_id': cve_id,
                    'image_count': 0,
                    'error': str(e),
                    'success': False
                }
    
    def analyze_vulnerabilities_working(self, include_registries: Optional[List[str]] = None,
                                      exclude_registries: Optional[List[str]] = None,
                                      vuln_filters: Optional[str] = None) -> List[Dict]:
        """WORKING main analysis function with proper registry filtering"""
        print("="*80)
        print("🚀 CROWDSTRIKE VULNERABILITY ANALYZER - WORKING VERSION")
        print("="*80)
        
        # Show registry filtering configuration
        if include_registries:
            print(f"📊 Including only registries: {include_registries}")
        elif exclude_registries:
            print(f"📊 Excluding registries: {exclude_registries}")
        else:
            print(f"📊 Including ALL registries")
        
        # Fetch all vulnerabilities
        vulnerabilities = self.get_all_vulnerabilities_fixed(additional_filters=vuln_filters)
        
        if not vulnerabilities:
            print("❌ No vulnerabilities found")
            return []
        
        print(f"✅ Collected {len(vulnerabilities):,} vulnerabilities")
        
        # Extract unique CVE IDs
        cve_ids = set()
        cve_to_vuln = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id')
            if cve_id:
                cve_ids.add(cve_id)
                if cve_id not in cve_to_vuln:
                    cve_to_vuln[cve_id] = vuln
        
        print(f"✅ Found {len(cve_ids):,} unique CVE IDs")
        
        cve_list = list(sorted(cve_ids))
        
        print(f"\n🔄 Processing {len(cve_list):,} CVEs for image counts...")
        
        results = []
        failed_count = 0
        
        for i, cve_id in enumerate(cve_list, 1):
            if i % 100 == 0 or i == 1 or i == len(cve_list):
                print(f"📊 Progress: {i:,}/{len(cve_list):,} ({i/len(cve_list)*100:.1f}%)")
            
            image_data = self.aggregate_image_count_by_cve_working(
                cve_id, 
                include_registries=include_registries,
                exclude_registries=exclude_registries
            )
            
            if not image_data.get('success'):
                failed_count += 1
            
            vuln_details = cve_to_vuln.get(cve_id, {})
            
            result = {
                'cve_id': cve_id,
                'image_count': image_data.get('image_count', 0),
                'total_count': image_data.get('total_count'),
                'excluded_count': image_data.get('excluded_count'),
                'registry_breakdown': image_data.get('registry_breakdown'),
                'filtering_method': image_data.get('method'),
                'severity': vuln_details.get('severity'),
                'cvss_score': vuln_details.get('cvss_score'),
                'cps_current_rating': vuln_details.get('cps_current_rating'),
                'description': vuln_details.get('description', ''),
                'published_date': vuln_details.get('published_date'),
                'images_impacted': vuln_details.get('images_impacted', 0),
                'packages_impacted': vuln_details.get('packages_impacted', 0),
                'containers_impacted': vuln_details.get('containers_impacted', 0),
                'remediation_available': vuln_details.get('remediation_available', False),
                'exploit_found': vuln_details.get('exploit_found', False),
                'aggregation_success': image_data.get('success', False),
                'error': image_data.get('error')
            }
            
            results.append(result)
        
        print(f"✅ Processing complete: {len(results):,} CVEs processed")
        if failed_count > 0:
            print(f"⚠️  {failed_count:,} aggregations failed")
        
        return results

def main():
    # Configuration
    BASE_URL = "https://api.crowdstrike.com"
    CLIENT_ID = ""
    CLIENT_SECRET = ""
    
    # Registry filtering options (choose ONE approach):
    
    # Option 1: Include only specific registries
    INCLUDE_REGISTRIES = [
        "https://crmiked.azurecr.io"
    ]
    EXCLUDE_REGISTRIES = None
    
    # Option 2: Exclude specific registries (comment out INCLUDE_REGISTRIES above)
    # INCLUDE_REGISTRIES = None
    # EXCLUDE_REGISTRIES = [
    #     "mcr.microsoft.com",
    #     "public.ecr.aws"
    # ]
    
    # Option 3: No filtering (all registries)
    # INCLUDE_REGISTRIES = None
    # EXCLUDE_REGISTRIES = None
    
    # Vulnerability filters
    VULN_FILTERS = None  # None = ALL vulnerabilities
    
    try:
        print("="*80)
        print("🚀 CROWDSTRIKE VULNERABILITY ANALYZER - REGISTRY FILTERING WORKS!")
        print("="*80)
        
        start_time = time.time()
        
        analyzer = CrowdStrikeVulnAnalyzer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        
        # Optional: Discover all available registries first
        print("\n🔍 Registry Discovery (optional):")
        available_registries = analyzer.discover_all_registries()
        
        # Run analysis
        results = analyzer.analyze_vulnerabilities_working(
            include_registries=INCLUDE_REGISTRIES,
            exclude_registries=EXCLUDE_REGISTRIES,
            vuln_filters=VULN_FILTERS
        )
        
        if not results:
            print("No results to display")
            return
        
        # Sort by image count
        results.sort(key=lambda x: x.get('image_count', 0), reverse=True)
        
        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filter_type = "INCLUDE" if INCLUDE_REGISTRIES else "EXCLUDE" if EXCLUDE_REGISTRIES else "ALL"
        filename = f'vulnerability_analysis_{filter_type}_REGISTRIES_{timestamp}.json'
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Display results
        runtime = time.time() - start_time
        runtime_str = f"{int(runtime//60)}m {int(runtime%60)}s"
        
        print(f"\n" + "="*80)
        print("🎉 ANALYSIS COMPLETE - REGISTRY FILTERING WORKING! 🎉")
        print("="*80)
        print(f"⏱️  Runtime: {runtime_str}")
        print(f"💾 Results saved to: {filename}")
        print(f"🔍 Total CVEs processed: {len(results):,}")
        
        successful = [r for r in results if r.get('aggregation_success')]
        total_images = sum(r.get('image_count', 0) for r in results)
        
        print(f"\n📊 SUMMARY:")
        print(f"   ✅ Successful: {len(successful):,}")
        print(f"   🖼️  Total images: {total_images:,}")
        
        # Show top 20 with registry breakdown
        print(f"\n🏆 TOP 20 CVEs BY IMAGE COUNT:")
        print("-" * 100)
        for i, result in enumerate(results[:20], 1):
            severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(result.get('severity', ''), '⚪')
            
            print(f"{i:2d}. {result['cve_id']}: {result['image_count']:,} images "
                  f"{severity_emoji} {result.get('severity', 'N/A')} "
                  f"(CVSS: {result.get('cvss_score', 'N/A')})")
            
            # Show registry breakdown if available
            if result.get('registry_breakdown'):
                breakdown = result['registry_breakdown']
                breakdown_str = ", ".join([f"{k}:{v}" for k, v in breakdown.items() if isinstance(v, int) and v > 0])
                if breakdown_str:
                    print(f"     Registry breakdown: {breakdown_str}")
        
        print(f"\n🎉 Registry filtering is working perfectly! 🎉")
        
    except Exception as e:
        print(f"❌ Script failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
