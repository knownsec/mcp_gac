import json
import logging
import os
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Dict, Any

import httpx
from dotenv import load_dotenv
from mcp.server import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GacMCPServer")
base_url = "https://gac.yunaq.com"


async def get_client():
    token = os.getenv("GAC_API_KEY")
    proxies = None
    https_proxy = os.getenv("https_proxy")
    http_proxy = os.getenv("http_proxy")
    if https_proxy or http_proxy:
        proxies = {}
        if https_proxy:
            proxies["https://"] = https_proxy
        if http_proxy:
            proxies["http://"] = http_proxy
    return httpx.AsyncClient(proxies=proxies, headers={"API-TOKEN": token, "Content-Type": "application/json"})


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[Dict[str, Any]]:
    """Manage server startup and shutdown lifecycle"""
    # We don't need to create a connection here since we're using the global connection
    # for resources and tools

    load_dotenv()
    yield {}


# Create the MCP server with lifespan support
mcp = FastMCP("GacMCP", description="Gac integration through the Model Context Protocol", lifespan=server_lifespan)


@mcp.tool()
async def analyze_ip(ip: str):
    """
    Comprehensive IP address analysis providing detailed security intelligence and reputation assessment.

    The `ip` parameter is a string representing IP address(es).
    It can contain:
    - A single IP address, for example: "8.8.8.8".
    - Multiple IP addresses separated by commas, for example: "8.8.8.8,1.1.1.1,114.114.114.114".

    When multiple IP addresses are provided:
    - Use a comma `,` as the separator.
    - A maximum of 100 IP addresses is supported per request.

    This function integrates IP analysis and IP reputation evaluation capabilities, returning complete IP intelligence information, including:
    - Basic information: Geographic location, ASN, ISP, etc.
    - Reputation scores: Threat level, trustworthiness, penetration testing capabilities, etc.
    - Threat intelligence: Attack history, device information, tags, etc.
    - Network information: Open ports, services, Whois information, etc.

    For inbound traffic scenarios, this analysis provides IP-related geographic location and ASN information,
    accurately determining whether an IP is malicious, its risk severity level, and trustworthiness level.
    It identifies threat types such as Command & Control (C2), Zombie machines, Compromised hosts,
    Scanners, Phishing, and related attack groups or security incidents.

    Args:
        ip (str): The IP address to analyze, one or more IP addresses, separated by commas if multiple (maximum 100 IP addresses)
    Returns:
        dict: Complete data containing IP analysis and reputation assessment
        The `data` field is always a list of dictionaries, each containing the analysis result and reputation assessment for one IP address:
        - For a single IP address, the list contains one dictionary
        - For multiple IP addresses, the list contains multiple dictionaries
    Raises:
        ValueError: If API key is not provided or API request fails
    """
    try:
        client = await get_client()
        async with client:
            # 并行请求两个API以提高效率
            analysis_task = client.get(f"{base_url}/api/v3/ip_analysis/{ip}")
            credit_task = client.get(f"{base_url}/api/v3/ip_credit/{ip}")

            analysis_response, credit_response = await asyncio.gather(analysis_task, credit_task)

            # 确保两个请求都成功
            analysis_response.raise_for_status()
            credit_response.raise_for_status()

            # 解析JSON响应
            raw_analysis_data = analysis_response.json()
            raw_credit_data = credit_response.json()

            # 合并结果
            analysis_data = raw_analysis_data.get("data", {})
            if isinstance(analysis_data, dict):
                analysis_data = [analysis_data]

            credit_data = raw_credit_data.get("data", {})
            if isinstance(credit_data, dict):
                credit_data = [credit_data]
            result = {
                "status": "success",
                "data": {
                    "ip": ip,
                    "analysis": analysis_data,
                    "credit": credit_data
                }
            }

            return result
    except httpx.HTTPError as e:
        raise ValueError(f"Error querying API: {str(e)}")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON response from API")
    except Exception as e:
        raise ValueError(f"Error analyzing IP: {str(e)}")


@mcp.tool()
async def analyze_domain(domain: str):
    """
    Comprehensive domain analysis providing detailed security intelligence and reputation assessment.

    The `domain` parameter is a string representing domain name(s).
    It can contain:
    - A single domain, for example: "example.com".
    - Multiple domains separated by commas, for example: "example.com,example.org,foo.bar".

    When multiple domains are provided:
    - Use a comma `,` as the separator.
    - A maximum of 50 domains is supported per request.

    This function integrates domain analysis and domain reputation evaluation capabilities, returning complete domain intelligence information, including:
    - Basic information: Registration details, DNS records, resolved IPs, etc.
    - Reputation scores: Threat level, trustworthiness, security assessment, etc.
    - Threat intelligence: Historical security incidents, associated malicious activities, etc.
    - Network information: Whois information, certificate details, etc.

    Args:
        domain (str): The domain to analyze, one or more domain names, separated by commas if multiple(maximum 50 domains)
    Returns:
        dict: Complete data containing domain analysis and reputation assessment
        The `data` field is always a list of dictionaries, each containing the analysis result and reputation assessment for one domain:
        - For a single domain, the list contains one dictionary.
        - For multiple domains, the list contains multiple dictionaries.
    Raises:
        ValueError: If API key is not provided or API request fails
    """
    try:
        client = await get_client()
        async with client:
            # 并行请求两个API以提高效率
            analysis_task = client.get(f"{base_url}/api/v3/domain_analysis/{domain}")
            credit_task = client.get(f"{base_url}/api/v3/domain_credit/{domain}")

            analysis_response, credit_response = await asyncio.gather(analysis_task, credit_task)

            # 确保两个请求都成功
            analysis_response.raise_for_status()
            credit_response.raise_for_status()

            # 解析JSON响应
            raw_analysis_data = analysis_response.json()
            raw_credit_data = credit_response.json()

            # 合并结果
            analysis_data = raw_analysis_data.get("data", {})
            if isinstance(analysis_data, dict):
                analysis_data = [analysis_data]

            credit_data = raw_credit_data.get("data", {})
            if isinstance(credit_data, dict):
                credit_data = [credit_data]
            result = {
                "status": "success",
                "data": {
                    "domain": domain,
                    "analysis": analysis_data,
                    "credit": credit_data
                }
            }

            return result
    except httpx.HTTPError as e:
        raise ValueError(f"Error querying API: {str(e)}")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON response from API")
    except Exception as e:
        raise ValueError(f"Error analyzing domain: {str(e)}")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
