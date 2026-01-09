"""
Burp Suite Request Parser

Utilities for parsing various Burp Suite export formats:
- Raw HTTP request/response text (copy-paste from Burp)
- XML exports
- JSON exports
- HAR files
"""

from typing import Dict, Optional, Tuple
import re


class HTTPParser:
    """
    Reusable HTTP request/response parser for raw text input.
    Designed to work with Burp Suite copy-paste output.
    """
    
    @staticmethod
    def parse_request(raw_http: str) -> Dict:
        """
        Parse raw HTTP request text into structured format.
        
        Args:
            raw_http (str): Raw HTTP request text from Burp Suite
            
        Returns:
            Dict: Parsed request data with keys:
                - method: HTTP method (GET, POST, etc.)
                - endpoint: Request path and query string
                - url: Full URL if Host header present
                - headers: Dict of header name -> value
                - body: Request body (empty string if none)
                - protocol: HTTP version
                - error_message: Error description if parsing failed
                
        Example input:
            POST /api/login HTTP/1.1
            Host: example.com
            Content-Type: application/json
            
            {"username":"admin","password":"pass123"}
        """
        result = {
            "method": None,
            "endpoint": None,
            "url": None,
            "headers": {},
            "body": "",
            "protocol": None,
            "error_message": None
        }
        
        try:
            if not raw_http or not raw_http.strip():
                result["error_message"] = "Empty request data"
                return result
            
            # Split request into lines
            lines = raw_http.strip().split('\n')
            
            # Parse request line (first line)
            request_line = lines[0].strip()
            request_parts = request_line.split(' ')
            
            if len(request_parts) < 3:
                result["error_message"] = "Invalid request line format"
                return result
            
            result["method"] = request_parts[0]
            result["endpoint"] = request_parts[1]
            result["protocol"] = request_parts[2]
            
            # Parse headers
            header_end_index = 1
            for i in range(1, len(lines)):
                line = lines[i].strip()
                
                # Empty line indicates end of headers
                if not line:
                    header_end_index = i
                    break
                
                # Parse header
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    result["headers"][header_name.strip()] = header_value.strip()
                else:
                    # Malformed header, but continue
                    continue
            
            # Parse body (everything after empty line)
            if header_end_index < len(lines) - 1:
                body_lines = lines[header_end_index + 1:]
                result["body"] = '\n'.join(body_lines).strip()
            
            # Construct full URL if Host header present
            if "Host" in result["headers"]:
                protocol = "https" if result["headers"].get("Host").startswith("https://") else "https"
                host = result["headers"]["Host"]
                result["url"] = f"{protocol}://{host}{result['endpoint']}"
            
        except Exception as e:
            result["error_message"] = f"Parsing error: {str(e)}"
        
        return result
    
    @staticmethod
    def parse_response(raw_http: str) -> Dict:
        """
        Parse raw HTTP response text into structured format.
        
        Args:
            raw_http (str): Raw HTTP response text from Burp Suite
            
        Returns:
            Dict: Parsed response data with keys:
                - status_code: HTTP status code (int)
                - status_message: Status text (e.g., "OK", "Not Found")
                - protocol: HTTP version
                - headers: Dict of header name -> value
                - body: Response body
                - response_length: Length of response body in bytes
                - error_message: Error description if parsing failed
                
        Example input:
            HTTP/1.1 200 OK
            Content-Type: application/json
            Set-Cookie: session=abc123
            
            {"token":"xyz789","user_id":42}
        """
        result = {
            "status_code": None,
            "status_message": None,
            "protocol": None,
            "headers": {},
            "body": "",
            "response_length": 0,
            "error_message": None
        }
        
        try:
            if not raw_http or not raw_http.strip():
                result["error_message"] = "Empty response data"
                return result
            
            # Split response into lines
            lines = raw_http.strip().split('\n')
            
            # Parse status line (first line)
            status_line = lines[0].strip()
            status_parts = status_line.split(' ', 2)
            
            if len(status_parts) < 2:
                result["error_message"] = "Invalid response status line format"
                return result
            
            result["protocol"] = status_parts[0]
            
            try:
                result["status_code"] = int(status_parts[1])
            except ValueError:
                result["error_message"] = f"Invalid status code: {status_parts[1]}"
                return result
            
            if len(status_parts) >= 3:
                result["status_message"] = status_parts[2]
            
            # Parse headers
            header_end_index = 1
            for i in range(1, len(lines)):
                line = lines[i].strip()
                
                # Empty line indicates end of headers
                if not line:
                    header_end_index = i
                    break
                
                # Parse header
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    result["headers"][header_name.strip()] = header_value.strip()
            
            # Parse body (everything after empty line)
            if header_end_index < len(lines) - 1:
                body_lines = lines[header_end_index + 1:]
                result["body"] = '\n'.join(body_lines).strip()
                result["response_length"] = len(result["body"].encode('utf-8'))
            
        except Exception as e:
            result["error_message"] = f"Parsing error: {str(e)}"
        
        return result
    
    @staticmethod
    def parse_request_response_pair(raw_request: str, raw_response: str) -> Dict:
        """
        Parse both HTTP request and response as a pair.
        
        Args:
            raw_request (str): Raw HTTP request text
            raw_response (str): Raw HTTP response text
            
        Returns:
            Dict: Combined parsed data with keys:
                - request: Parsed request dict
                - response: Parsed response dict
                - has_errors: Boolean indicating if either parsing failed
        """
        request_data = HTTPParser.parse_request(raw_request)
        response_data = HTTPParser.parse_response(raw_response)
        
        return {
            "request": request_data,
            "response": response_data,
            "has_errors": bool(request_data.get("error_message") or response_data.get("error_message"))
        }
    
    @staticmethod
    def extract_authentication_headers(parsed_request: Dict) -> Dict:
        """
        Extract authentication-related headers from parsed request.
        
        Args:
            parsed_request (Dict): Output from parse_request()
            
        Returns:
            Dict: Authentication headers including:
                - authorization: Authorization header value
                - cookies: Cookie header value
                - bearer_token: Extracted Bearer token if present
                - api_key: API key if present in headers
        """
        headers = parsed_request.get("headers", {})
        auth_data = {
            "authorization": None,
            "cookies": None,
            "bearer_token": None,
            "api_key": None
        }
        
        # Check for Authorization header
        for header_name, header_value in headers.items():
            if header_name.lower() == "authorization":
                auth_data["authorization"] = header_value
                # Extract Bearer token if present
                if header_value.startswith("Bearer "):
                    auth_data["bearer_token"] = header_value.split("Bearer ", 1)[1]
            elif header_name.lower() == "cookie":
                auth_data["cookies"] = header_value
            elif header_name.lower() in ["x-api-key", "api-key"]:
                auth_data["api_key"] = header_value
        
        return auth_data
    
    @staticmethod
    def extract_authentication_response_data(parsed_response: Dict) -> Dict:
        """
        Extract authentication-related data from parsed response.
        
        Args:
            parsed_response (Dict): Output from parse_response()
            
        Returns:
            Dict: Authentication response data including:
                - set_cookies: List of Set-Cookie header values
                - tokens_in_body: Dict of potential tokens found in response body
                - auth_headers: Dict of authentication-related response headers
        """
        headers = parsed_response.get("headers", {})
        body = parsed_response.get("body", "")
        
        auth_data = {
            "set_cookies": [],
            "tokens_in_body": {},
            "auth_headers": {}
        }
        
        # Extract Set-Cookie headers
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                auth_data["set_cookies"].append(header_value)
            elif header_name.lower() in ["authorization", "www-authenticate", "x-auth-token"]:
                auth_data["auth_headers"][header_name] = header_value
        
        # Search for common token patterns in body
        if body:
            token_patterns = {
                "token": r'"token"\s*:\s*"([^"]+)"',
                "access_token": r'"access_token"\s*:\s*"([^"]+)"',
                "refresh_token": r'"refresh_token"\s*:\s*"([^"]+)"',
                "session_id": r'"session(?:_id)?"\s*:\s*"([^"]+)"',
                "jwt": r'"jwt"\s*:\s*"([^"]+)"'
            }
            
            for token_name, pattern in token_patterns.items():
                match = re.search(pattern, body)
                if match:
                    auth_data["tokens_in_body"][token_name] = match.group(1)
        
        return auth_data
