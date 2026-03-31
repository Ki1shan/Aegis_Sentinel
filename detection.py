from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
import random
import math


@dataclass
class ThreatAnalysis:
    threat_score: float
    risk_level: str
    severity: str
    detected_patterns: list
    recommendations: list
    confidence: float


class ThreatDetector:
    SUSPICIOUS_HEADERS = {
        'x-originating-ip': 0.3,
        'x-forwarded-for': 0.1,
        'x-real-ip': 0.1,
        'cf-connecting-ip': 0.2,
        'true-client-ip': 0.2,
        'x-hacker': 0.5,
        'x-attacktag': 0.6,
        'x-security': 0.4,
    }
    
    KNOWN_BOT_PATTERNS = [
        'curl', 'wget', 'python', 'requests', 'scrapy', 'bot', 'crawler', 
        'spider', 'scan', 'nmap', 'sqlmap', 'hydra', 'metasploit', 'nikto',
        'masscan', 'zgrab', 'httpie', 'postman', 'insomnia', 'burp'
    ]
    
    SUSPICIOUS_PATHS = [
        '/admin', '/wp-login', '/wp-admin', '/phpmyadmin', '/.env', '/.git',
        '/config', '/backup', '/api/v1', '/xmlrpc.php', '/wp-config.php',
        '/administrator', '/admin/login', '/manager/html', '/console'
    ]
    
    SUSPICIOUS_USER_AGENTS = [
        'masscan', 'zmap', 'nmap', 'sqlmap', 'nikto', 'dirbuster', 'gobuster',
        'hydra', 'medusa', 'hydra', 'crack', 'exploit', 'scanner'
    ]
    
    def __init__(self):
        self.ml_model_weights = {
            'request_rate': 0.25,
            'pattern_match': 0.20,
            'header_analysis': 0.15,
            'behavioral': 0.25,
            'reputation': 0.15
        }
    
    def analyze_request(
        self,
        ip_address: str,
        headers: dict,
        user_agent: str,
        path: str,
        request_count: int,
        window_seconds: int,
        time_since_first_request: float,
        unique_paths: int = 1,
        unique_agents: int = 1,
        recent_requests: int = 0
    ) -> ThreatAnalysis:
        scores = {}
        detected_patterns = []
        recommendations = []
        
        scores['request_rate'] = self._analyze_request_rate(request_count, window_seconds)
        if scores['request_rate'] > 0.5:
            detected_patterns.append(f"Rapid requests: {request_count} in {window_seconds}s")
            recommendations.append("Rate limiting should be enforced")
        
        scores['pattern_match'] = self._analyze_patterns(
            user_agent, path, headers
        )
        
        scores['header_analysis'] = self._analyze_headers(headers, user_agent)
        
        scores['behavioral'] = self._analyze_behavior(
            request_count, time_since_first_request, unique_paths, unique_agents, recent_requests
        )
        
        scores['reputation'] = self._analyze_reputation(ip_address, user_agent)
        
        final_score = sum(
            scores[key] * weight 
            for key, weight in self.ml_model_weights.items()
        )
        
        final_score = min(1.0, max(0.0, final_score))
        
        risk_level, severity = self._determine_risk_level(final_score)
        confidence = self._calculate_confidence(scores)
        
        if risk_level in ['high', 'critical']:
            recommendations.append("Consider IP blocking")
            recommendations.append("Enable enhanced monitoring")
        
        return ThreatAnalysis(
            threat_score=round(final_score, 3),
            risk_level=risk_level,
            severity=severity,
            detected_patterns=detected_patterns,
            recommendations=recommendations,
            confidence=round(confidence, 3)
        )
    
    def _analyze_request_rate(self, count: int, window: int) -> float:
        if window <= 0:
            return 0.0
        
        requests_per_second = count / window
        
        if requests_per_second > 1.0:
            return min(1.0, requests_per_second)
        elif requests_per_second > 0.5:
            return 0.6
        elif requests_per_second > 0.2:
            return 0.3
        else:
            base = requests_per_second * 0.5
            return min(0.5, base)
    
    def _analyze_patterns(self, user_agent: str, path: str, headers: dict) -> float:
        score = 0.0
        ua_lower = user_agent.lower()
        
        for pattern in self.KNOWN_BOT_PATTERNS:
            if pattern in ua_lower:
                score += 0.4
                break
        
        for pattern in self.SUSPICIOUS_PATHS:
            if path.lower().startswith(pattern) or pattern in path.lower():
                score += 0.3
                break
        
        ua_lower = user_agent.lower()
        for pattern in self.SUSPICIOUS_USER_AGENTS:
            if pattern in ua_lower:
                score += 0.5
                break
        
        if not user_agent or len(user_agent) < 10:
            score += 0.2
        
        if len(headers) < 3:
            score += 0.1
        
        return min(1.0, score)
    
    def _analyze_headers(self, headers: dict, user_agent: str) -> float:
        score = 0.0
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, weight in self.SUSPICIOUS_HEADERS.items():
            if header in headers_lower:
                score += weight
        
        if 'user-agent' not in headers_lower:
            score += 0.3
        
        suspicious_referers = ['http://', 'https://www.google.com', 'https://www.bing.com']
        referer = headers_lower.get('referer', '')
        if any(s in referer.lower() for s in suspicious_referers):
            score += 0.1
        
        if 'accept-language' not in headers_lower:
            score += 0.1
        
        return min(1.0, score)
    
    def _analyze_behavior(
        self,
        request_count: int,
        time_since_first: float,
        unique_paths: int,
        unique_agents: int,
        recent_requests: int
    ) -> float:
        score = 0.0
        
        if time_since_first > 0:
            requests_per_minute = (request_count / time_since_first) * 60
            if requests_per_minute > 60:
                score += 0.4
            elif requests_per_minute > 30:
                score += 0.2
            elif requests_per_minute > 10:
                score += 0.1
        
        if unique_agents > 3:
            score += 0.3
        elif unique_agents > 1:
            score += 0.1
        
        if request_count > 50:
            score += 0.3
        elif request_count > 20:
            score += 0.2
        elif request_count > 10:
            score += 0.1
        
        return min(1.0, score)
    
    def _analyze_reputation(self, ip_address: str, user_agent: str) -> float:
        score = 0.0
        
        if ip_address.startswith(('10.', '192.168.', '172.')):
            score = 0.0
        elif ip_address == '127.0.0.1':
            score = 0.0
        else:
            parts = ip_address.split('.')
            if len(parts) == 4:
                first_octet = int(parts[0]) if parts[0].isdigit() else 0
                if first_octet >= 224:
                    score += 0.4
                elif first_octet >= 192:
                    score += 0.1
        
        return min(1.0, score)
    
    def _determine_risk_level(self, score: float) -> tuple:
        if score >= 0.8:
            return 'critical', 'critical'
        elif score >= 0.6:
            return 'high', 'high'
        elif score >= 0.4:
            return 'medium', 'medium'
        elif score >= 0.2:
            return 'low', 'low'
        else:
            return 'minimal', 'low'
    
    def _calculate_confidence(self, scores: dict) -> float:
        values = list(scores.values())
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        
        confidence = 1.0 - min(0.5, std_dev)
        
        return max(0.0, min(1.0, confidence))


class MLThreatScorer:
    def __init__(self):
        self.feature_weights = {
            'request_frequency': 0.15,
            'session_duration': 0.10,
            'path_entropy': 0.12,
            'header_variance': 0.13,
            'temporal_pattern': 0.15,
            'geo_anomaly': 0.10,
            'behavior_anomaly': 0.15,
            'threat_history': 0.10
        }
        
        self.baseline_stats = {
            'avg_requests_per_min': 5.0,
            'avg_session_duration': 300.0,
            'avg_paths_per_session': 3.0
        }
    
    def calculate_threat_score(
        self,
        request_count: int,
        time_window: float,
        unique_paths: int,
        unique_headers: int,
        request_intervals: list,
        historical_score: float = 0.0
    ) -> dict:
        features = {}
        
        features['request_frequency'] = self._score_frequency(request_count, time_window)
        
        features['session_duration'] = self._score_duration(time_window)
        
        features['path_entropy'] = self._score_entropy(unique_paths, request_count)
        
        features['header_variance'] = self._score_header_variance(unique_headers)
        
        features['temporal_pattern'] = self._score_temporal(request_intervals)
        
        features['geo_anomaly'] = 0.0
        
        features['behavior_anomaly'] = self._score_behavior(
            request_count, unique_paths, time_window
        )
        
        features['threat_history'] = min(1.0, historical_score * 1.2)
        
        weighted_score = sum(
            features[key] * weight 
            for key, weight in self.feature_weights.items()
        )
        
        confidence = self._calculate_confidence(features)
        
        return {
            'score': round(weighted_score, 3),
            'features': {k: round(v, 3) for k, v in features.items()},
            'confidence': round(confidence, 3),
            'anomaly_detected': any(v > 0.7 for v in features.values())
        }
    
    def _score_frequency(self, count: int, window: float) -> float:
        if window <= 0:
            return 0.0
        
        rpm = (count / window) * 60
        
        if rpm > 100:
            return 1.0
        elif rpm > 50:
            return 0.8
        elif rpm > 20:
            return 0.5
        elif rpm > 10:
            return 0.3
        else:
            return rpm / 50
    
    def _score_duration(self, duration: float) -> float:
        if duration < 1:
            return 1.0
        elif duration < 5:
            return 0.8
        elif duration < 30:
            return 0.4
        elif duration < 120:
            return 0.2
        else:
            return 0.1
    
    def _score_entropy(self, unique_paths: int, total_requests: int) -> float:
        if total_requests == 0:
            return 0.0
        
        diversity = unique_paths / total_requests
        
        if diversity < 0.01 and total_requests > 10:
            return 0.8
        elif diversity < 0.05:
            return 0.4
        else:
            return diversity * 2
    
    def _score_header_variance(self, unique_headers: int) -> float:
        if unique_headers < 3:
            return 0.6
        elif unique_headers < 5:
            return 0.3
        else:
            return 0.1
    
    def _score_temporal(self, intervals: list) -> float:
        if len(intervals) < 2:
            return 0.0
        
        avg_interval = sum(intervals) / len(intervals)
        
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        
        if variance < 0.1 and avg_interval < 0.5:
            return 0.9
        elif variance < 0.5:
            return 0.5
        else:
            return 0.2
    
    def _score_behavior(self, requests: int, paths: int, duration: float) -> float:
        if duration <= 0:
            return 0.0
        
        requests_per_second = requests / duration
        
        if requests_per_second > 1:
            return 0.9
        elif requests_per_second > 0.5:
            return 0.6
        elif requests_per_second > 0.1:
            return 0.3
        else:
            return 0.1
    
    def _calculate_confidence(self, features: dict) -> float:
        non_zero = sum(1 for v in features.values() if v > 0)
        return min(1.0, non_zero / len(features))
    
    def predict_threat_category(self, features: dict) -> str:
        if features.get('request_frequency', 0) > 0.8:
            return 'ddos'
        elif features.get('behavior_anomaly', 0) > 0.7:
            return 'bruteforce'
        elif features.get('path_entropy', 0) > 0.6:
            return 'scanning'
        elif features.get('header_variance', 0) > 0.5:
            return 'bot'
        else:
            return 'unknown'


threat_detector = ThreatDetector()
ml_scorer = MLThreatScorer()
