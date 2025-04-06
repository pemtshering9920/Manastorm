# Manastorm
#### Manastorm V1.0 (Scaled Down to Basic Implementation) - Engineered by @KnottyEngineer aka RastaMouse.

#### Important Disclaimer:

Manastorm is a DDoS stress testing tool created exclusively for internal web penetration testing within controlled environments. This tool is created to simulate Layer 3 (network layer) and Layer 7 (application layer) attack vectors to assess the resilience of web applications and networks, as part of my Cybersecurity Research. The primary intent of Manastorm is for ethical hacking and stress-testing in controlled environments. By sharing the tool on GitHub, I aim to provide researchers, developers, and cybersecurity enthusiasts with a resource to understand network behavior, security vulnerabilities, and stress testing in a safe and legal manner.  Many cybersecurity tools are released for research purposes to study attack vectors, response times, and system resilience. Manastorm would help users learn how DDoS attacks work, the mitigation strategies that can be employed, and how to better defend systems.

#### By using Manastorm, you acknowledge and agree to the following:

1. Internal Use Only: This tool is strictly for internal web penetration testing in environments where 
    you have explicit authorization to perform stress tests or security assessments. Manastorm is not to 
    be used for attacking any system, network, or application without proper consent from the system owner.

2. Ethical Use: You are responsible for ensuring that this tool is only used within an environment where 
    you have the right to conduct stress tests. Do not use Manastorm on any live, production systems or any 
    external systems without prior written consent.

3. Legal Compliance: Unauthorized use of this tool for stress testing or DDoS attacks against systems 
    without permission is illegal and punishable under computer crime laws in various jurisdictions. Ensure 
    that all usage is compliant with local laws and regulations.

4. No Malicious Intent: Manastorm must not be used for malicious purposes. Any unauthorized or harmful use 
    of this tool is your responsibility. The developers are not liable for any damage or legal consequences arising 
    from misuse.

5. Testing Scope: Always test within controlled, isolated environments such as internal networks or systems that 
    you own or have written permission to test. Never use this tool on third-party services without explicit authorization.

6. No Warranty: Manastorm is provided as-is, without any guarantees or warranties. The developers are not responsible 
    for any issues that arise from the use or misuse of this tool.


Manastorm Execution Syntax:
`python3 manastorm.py <target> [duration] [options]`

Required Arguments:

    <target>: URL or IP address of the target (use http/https for websites).

Optional Arguments:

    [duration]:Duration of the attack in seconds (default: 300 seconds).

    [options]: Special flags for configuring attack modes.


______________________________________________________________


Execution Examples:

1. Basic Website Stress Test (5 minutes):

        sudo python3 manastorm.py https://example.com

        Note: sudo is required for raw socket access to simulate Layer 3 attacks.

2. Targeted Port Attack (2 minutes):

        sudo python3 manastorm.py 192.168.1.100 120 --port 80

4. Stealth Mode Attack (Slower, less detectable):

        sudo python3 manastorm.py https://example.com 600 --stealth

5. Maximum Power Mode (All attack vectors):

        sudo python3 manastorm.py https://example.com 300 --full-power



Available Command Line Options:

Option	    Description	   Example

--port X	(Target specific port)	    --port 443

--stealth	(Enable stealth mode (slower, less detectable))	--stealth

--full-power	(Enable all attack vectors)	--full-power

--no-ssl	(Disable SSL verification)	--no-ssl

--threads X	(Set custom thread count)	--threads 1000

--debug	(Enable verbose error output)	--debug






#### Real-World Test Cases:

Testing an HTTP Website:

    sudo python3 manastorm.py http://testphp.vulnweb.com 180

Testing an API Endpoint:

    sudo python3 manastorm.py https://api.example.com/v1 --port 443 --threads 500

Testing Network Infrastructure:

    sudo python3 manastorm.py 10.0.0.5 300 --full-power


Important Notes:

    Always run with sudo for Layer 3 attacks (raw socket access is required):

sudo python3 manastorm.py [target]

#### Legal Testing: Always ensure that you have written consent to test the target system. You can legally test internal systems or approved test environments like:

        http://testphp.vulnweb.com

        http://demo.testfire.net

CTRL+C will gracefully stop all active attacks.

NOTE: ALL FEATURES DESCRIBED IN THIS SCALED DOWN BASIC VERSION MAY NOT RUN AS INTENDED.
