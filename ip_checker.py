#!/usr/bin/env python3
"""
IP Reputation Checker Tool
Created by: Abdul Muqeet Tabraiz
Version: 1.0.0
Description: Query AbuseIPDB and VirusTotal APIs for IP reputation data
"""

import os
import sys
import json
import time
import requests
from datetime import datetime
from dotenv import load_dotenv
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Load environment variables
load_dotenv()

class IPReputationChecker:
    """Main class for checking IP reputation across multiple services"""
    
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.results = {}
        
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     {Fore.YELLOW}IP REPUTATION CHECKER TOOL{Fore.CYAN}                               ║
║     {Fore.GREEN}Version: 1.0.0{Fore.CYAN}                                           ║
║     {Fore.GREEN}Created by: Abdul Muqeet Tabraiz{Fore.CYAN}                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def validate_ip(self, ip):
        """Basic IP validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True
    
    def get_abuseipdb_data(self, ip):
        """Query AbuseIPDB API"""
        print(f"{Fore.YELLOW}[*] Querying AbuseIPDB...{Style.RESET_ALL}")
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'abuseipdb': {
                        'score': data.get('abuseConfidenceScore', None),
                        'country': data.get('countryCode', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'domain': data.get('domain', 'Unknown'),
                        'usage_type': data.get('usageType', 'Unknown'),
                        'total_reports': data.get('totalReports', 0),
                        'last_reported': data.get('lastReportedAt', 'Never') or 'Never'
                    }
                }
            else:
                print(f"{Fore.RED}[!] AbuseIPDB Error: {response.status_code}{Style.RESET_ALL}")
                return {'abuseipdb': {'error': f'Status Code: {response.status_code}'}}
        except Exception as e:
            print(f"{Fore.RED}[!] AbuseIPDB Request Failed: {str(e)}{Style.RESET_ALL}")
            return {'abuseipdb': {'error': str(e)}}
    
    def get_virustotal_data(self, ip):
        """Query VirusTotal API"""
        print(f"{Fore.YELLOW}[*] Querying VirusTotal...{Style.RESET_ALL}")
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {
            'x-apikey': self.virustotal_key,
            'Accept': 'application/json'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                
                # Calculate malicious count
                stats = data.get('last_analysis_stats', {})
                total_engines = sum(stats.values()) if stats else 1
                malicious = stats.get('malicious', 0)
                detection_rate = (malicious / total_engines * 100) if total_engines > 0 else 0
                
                return {
                    'virustotal': {
                        'detection_rate': round(detection_rate, 2),
                        'malicious_votes': malicious,
                        'total_engines': total_engines,
                        'country': data.get('country', 'Unknown'),
                        'network': data.get('network', 'Unknown'),
                        'as_owner': data.get('as_owner', 'Unknown'),
                        'reputation': data.get('reputation', 0),
                        'last_analysis': data.get('last_analysis_date', 0)
                    }
                }
            else:
                print(f"{Fore.RED}[!] VirusTotal Error: {response.status_code}{Style.RESET_ALL}")
                return {'virustotal': {'error': f'Status Code: {response.status_code}'}}
        except Exception as e:
            print(f"{Fore.RED}[!] VirusTotal Request Failed: {str(e)}{Style.RESET_ALL}")
            return {'virustotal': {'error': str(e)}}
    
    def calculate_risk_level(self, abuse_score, vt_detection_rate):
        """Calculate overall risk level"""
        try:
            avg_score = (abuse_score + vt_detection_rate) / 2
            
            if avg_score >= 70:
                return "CRITICAL", Fore.RED
            elif avg_score >= 40:
                return "HIGH", Fore.RED
            elif avg_score >= 20:
                return "MEDIUM", Fore.YELLOW
            elif avg_score >= 5:
                return "LOW", Fore.GREEN
            else:
                return "SAFE", Fore.GREEN
        except:
            return "UNKNOWN", Fore.WHITE
    
    def format_timestamp(self, timestamp):
        """Convert Unix timestamp to readable format"""
        if timestamp:
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return 'N/A'
    
    def display_results(self):
        """Display results in terminal"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}IP REPUTATION CHECK RESULTS")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        ip = self.results.get('ip', 'Unknown')
        print(f"{Fore.WHITE}Target IP: {Fore.GREEN}{ip}")
        print(f"{Fore.WHITE}Scan Time: {Fore.GREEN}{self.results.get('scan_time', 'Unknown')}")
        print()
        
        # AbuseIPDB Results
        print(f"{Fore.CYAN}{'─'*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}ABUSEIPDB RESULTS")
        print(f"{Fore.CYAN}{'─'*60}")
        
        abuse_data = self.results.get('abuseipdb', {})
        if 'error' not in abuse_data:
            score = abuse_data.get('score', 0)
            score_color = Fore.RED if score > 50 else Fore.GREEN
            
            print(f"{Fore.WHITE}Confidence Score: {score_color}{score}%")
            print(f"{Fore.WHITE}Country: {Fore.GREEN}{abuse_data.get('country', 'N/A')}")
            print(f"{Fore.WHITE}ISP: {Fore.GREEN}{abuse_data.get('isp', 'N/A')}")
            print(f"{Fore.WHITE}Domain: {Fore.GREEN}{abuse_data.get('domain', 'N/A')}")
            print(f"{Fore.WHITE}Usage Type: {Fore.GREEN}{abuse_data.get('usage_type', 'N/A')}")
            print(f"{Fore.WHITE}Total Reports: {Fore.YELLOW}{abuse_data.get('total_reports', 0)}")
            print(f"{Fore.WHITE}Last Reported: {Fore.YELLOW}{abuse_data.get('last_reported', 'Never')}")
        else:
            print(f"{Fore.RED}Error: {abuse_data.get('error', 'Unknown error')}")
        
        print()
        
        # VirusTotal Results
        print(f"{Fore.CYAN}{'─'*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}VIRUSTOTAL RESULTS")
        print(f"{Fore.CYAN}{'─'*60}")
        
        vt_data = self.results.get('virustotal', {})
        if 'error' not in vt_data:
            detection_rate = vt_data.get('detection_rate', 0)
            rate_color = Fore.RED if detection_rate > 20 else Fore.GREEN
            
            print(f"{Fore.WHITE}Detection Rate: {rate_color}{detection_rate}%")
            print(f"{Fore.WHITE}Malicious Votes: {Fore.RED}{vt_data.get('malicious_votes', 0)}/{vt_data.get('total_engines', 0)}")
            print(f"{Fore.WHITE}Country: {Fore.GREEN}{vt_data.get('country', 'N/A')}")
            print(f"{Fore.WHITE}Network: {Fore.GREEN}{vt_data.get('network', 'N/A')}")
            print(f"{Fore.WHITE}AS Owner: {Fore.GREEN}{vt_data.get('as_owner', 'N/A')}")
            print(f"{Fore.WHITE}Reputation Score: {Fore.YELLOW}{vt_data.get('reputation', 0)}")
            print(f"{Fore.WHITE}Last Analysis: {Fore.GREEN}{self.format_timestamp(vt_data.get('last_analysis', 0))}")
        else:
            print(f"{Fore.RED}Error: {vt_data.get('error', 'Unknown error')}")
        
        print()
        
        # Overall Risk Assessment
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}OVERALL RISK ASSESSMENT")
        print(f"{Fore.CYAN}{'='*60}")
        
        abuse_score = abuse_data.get('score', 0) if 'error' not in abuse_data else 0
        vt_detection = vt_data.get('detection_rate', 0) if 'error' not in vt_data else 0
        
        risk_level, risk_color = self.calculate_risk_level(abuse_score, vt_detection)
        
        print(f"{Fore.WHITE}Risk Level: {risk_color}{Style.BRIGHT}{risk_level}")
        print(f"{Fore.WHITE}AbuseIPDB Score: {Fore.YELLOW}{abuse_score}%")
        print(f"{Fore.WHITE}VirusTotal Detection: {Fore.YELLOW}{vt_detection}%")
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def save_results(self, ip):
        """Save results to JSON file"""
        if not os.path.exists('results'):
            os.makedirs('results')
        
        filename = f"results/ip_check_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"{Fore.GREEN}[✓] Results saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save results: {str(e)}{Style.RESET_ALL}")
    
    def check_ip(self, ip):
        """Main method to check IP reputation"""
        if not self.validate_ip(ip):
            print(f"{Fore.RED}[!] Invalid IP address format{Style.RESET_ALL}")
            return False
        
        self.print_banner()
        print(f"{Fore.CYAN}[+] Checking IP: {Fore.GREEN}{ip}{Style.RESET_ALL}\n")
        
        self.results = {
            'ip': ip,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tool_creator': 'Abdul Muqeet Tabraiz'
        }
        
        # Query both APIs
        if self.abuseipdb_key and self.abuseipdb_key != 'your_abuseipdb_api_key_here':
            self.results.update(self.get_abuseipdb_data(ip))
        else:
            print(f"{Fore.YELLOW}[!] AbuseIPDB API key not configured - skipping{Style.RESET_ALL}")
            self.results['abuseipdb'] = {'error': 'API key not configured'}
        
        time.sleep(1)  # Small delay between API calls
        
        if self.virustotal_key and self.virustotal_key != 'your_virustotal_api_key_here':
            self.results.update(self.get_virustotal_data(ip))
        else:
            print(f"{Fore.YELLOW}[!] VirusTotal API key not configured - skipping{Style.RESET_ALL}")
            self.results['virustotal'] = {'error': 'API key not configured'}
        
        # Display and save results
        self.display_results()
        self.save_results(ip)
        
        return True

def main():
    """Main function"""
    checker = IPReputationChecker()
    
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        checker.print_banner()
        print(f"{Fore.CYAN}Usage: python ip_checker.py <IP_ADDRESS>{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Example: python ip_checker.py 8.8.8.8{Style.RESET_ALL}\n")
        ip = input(f"{Fore.GREEN}Enter IP address to check: {Style.RESET_ALL}").strip()
    
    if ip:
        checker.check_ip(ip)

if __name__ == "__main__":
    main()