# 🚀 Yunaq GAC MCP Server

A Model Context Protocol (MCP) server that provides comprehensive IP and domain intelligence. This server allows Large Language Models (LLMs) to obtain detailed security information, reputation assessments, and threat intelligence by analyzing IP addresses and domains through the Yunaq GAC platform.

## 🔔 Announcement

🎉 Welcome to the **Yunaq GAC MCP Server** — a powerful Model Context Protocol (MCP) server that brings comprehensive IP and domain intelligence to AI assistants and development environments.

🔍 Analyze IP addresses and domains to get detailed security information, reputation assessments, and threat intelligence — all in one place.

💡 Key features include:

1. Comprehensive IP and domain analysis
2. Detailed reputation scoring and threat intelligence
3. Parallel API requests for improved performance
4. Complete security context in a single call

🔧 Fully compatible with leading MCP environments:

- Claude Desktop
- Cursor
- Windsurf
- Cline
- Continue
- Zed
- Cherry Studio
- Chatbox

🔗 Explore Yunaq GAC MCP Server on:

- GitHub: [knownsec/mcp_gac](https://github.com/knownsec/mcp_gac)

We welcome everyone to use, explore, and contribute!

## 🔑 How can I get a Yunaq GAC API key?

To use this MCP server, you'll need a Yunaq GAC API key.

1. Go to https://gac.yunaq.com/doc/api?section=token
2. Register or log in
3. Navigate to docs -> token
4. Copy your **API-TOKEN**
5. Set the environment variable:
   
   `export GAC_API_KEY="your_api_key_here"`

## Features

- Comprehensive IP and domain intelligence analysis
- Parallel API requests for improved performance
- Detailed security information including reputation scores and threat intelligence
- Comprehensive error handling and logging

## Available Tools

- `analyze_ip` - Comprehensive IP address analysis providing detailed security intelligence and reputation assessment.
  - Required parameters:
    - `ip` (string): The IP address to analyze
  - Returns:
    - Complete data containing IP analysis and reputation assessment, including:
      - Basic information: Geographic location, ASN, ISP, etc.
      - Reputation scores: Threat level, trustworthiness, penetration testing capabilities
      - Threat intelligence: Attack history, device information, tags
      - Network information: Open ports, services, Whois information

- `analyze_domain` - Comprehensive domain analysis providing detailed security intelligence and reputation assessment.
  - Required parameters:
    - `domain` (string): The domain to analyze
  - Returns:
    - Complete data containing domain analysis and reputation assessment, including:
      - Basic information: Registration details, DNS records, resolved IPs
      - Reputation scores: Threat level, trustworthiness, security assessment
      - Threat intelligence: Historical security incidents, associated malicious activities
      - Network information: Whois information, certificate details

## Installation

### Using PIP

Alternatively, you can install `mcp-server-gac` via pip:

```bash
pip install mcp-server-gac
```
### Using MCP Inspector

The Model Context Protocol Inspector is a tool that helps debug MCP servers by simulating client interactions. You can use it to test your Yunaq GAC MCP server:

```bash
python -m mcp_server_gac
```

### Common Issues

1. **Authentication Errors**
   
   - Ensure your Yunaq GAC API key is correct and properly set as an environment variable
   - Check that your API key has not expired or been revoked
2. **Connection Issues**
   
   - Verify your internet connection
   - Check if the Yunaq GAC API is experiencing downtime
3. **No Results**
   
   - Your query might be too specific or contain syntax errors
   - Try simplifying your query or using different search terms
4. **Rate Limiting**
   
   - Yunaq GAC API has rate limits based on your account type
   - Space out your requests or upgrade your account for higher limits


### Parallel Requests

The Yunaq GAC MCP server implements parallel requests to improve performance:

- Multiple API endpoints are queried simultaneously
- Results are combined into a single comprehensive response
- This provides a complete view of security intelligence in a single call



## License

mcp-server-gac is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more information, see the LICENSE file in the project repository.