# Architecture and Design for CompTIA Security+

### Understanding Security Concepts in an Enterprise Environment
* Configuration Management
  * The management and control of configurations for an information system with the goal of enabling security and managing risk
    * Standardize the Environment
    * Set baselines to Understand "normal"
    * Identify conflicts/collisions
  * Method of determining what's normal
    * Changes can quickly be identified
    * Patches/updates, etc. can be determined successful or failed quickly
    * Changes throughout an enterprise are documented, discussed and any potential collisions determined
* Diagrams
  * Diagraming visualizes how things work, connected and interpolate
    * Dependencies are identified and documented
    * Inputs and outputs understood
    * Security risks can be discovered and mitigated
    * Applications, networking, compute, storage, etc.
* Baseline Configuration
  * Setting baselines is critical to quickly identifying changes, configuration drift, etc.
  * When hackers or bad actors enter a system or network, they change things
    * Changes can be discovered more quickly because they're outside the norm or baseline
  * Standardization
    * The more standardized things are, the easier they are to maintain, deploy and troubleshoot
* IP Address Schema
  * Standardize
  * Maintain an IP address database
    * Allocations and reclamations
  *  Tools:
     *  IP control (IPAM)
        *  Simplifies management
        *  Makes troubleshooting easier
        *  Increases Security
* Data Sovereignty
  * When data is stored electronically, it is subject to the laws of the country in which it's located
    * Who owns the data/has access?
    * Who can mine the data?
  * Laws governing data use, access, storage and deletion vary from country to country
* Data Loss Prevention (DLP)
  * Data Loss Prevention (DLP) detects potential breaches and exfiltration of data
    * Endpoint detection (in use)
    * Network Traffic (in transit)
    * Data Storage (at rest)
  * Additional methods
    * USB Blocking
    * Cloud-based
    * Email
* Types of Data to Secure
  * Data at rest
    * Data sitting on a hard drive or removable media
    * Local to the computer or remotely on SAN or NAS storage
  * Data In-transit
    * Data that is being sent over a wired or wireless network
    * VPN connection will encrypt the data while in transit (wired or wireless)
  * Data in-use
    * Data not "at rest" and only on one particular node on a network
    * Could be memory resident, swap/temp space, etc.
* Data Masking
  * Hiding data
  * Can be done within applications, databases, etc., at the individual record, row, column or entire table
  * IP address masking
    * Network Address Translation (NAT) enables private IP addresses to be masked behind a proxy or firewall
  * Can be Static or dynamic
    * Data-at-rest or data in transit, and can be done via a variety of methods (encryption, substitution, nulling, tokenization, etc.)
* Tokenization
  * Tokenization is replacing sensitive data with non-sensitive equivalent. The token can be single use, multiple use, cryptographic or non-cryptographic, reversible or irreversible, etc.
    * Hight-value tokens (HVTs) can be used to replace things like primary account numbers on credit cards transactions, can be bound to specific devices, etc.
    * Low-value tokens (LVTs) Can serve similar functions but needs the underlying tokenization system to match it back to the actual PAN
  * Tokenization Example
    1. Customer makes purchase, token goes to merchant
    2. Merchant passes the token along to merchant acquirer
    3. Merchant acquirer passes the token to the network
    4. Data then resides inside secure "bank vault"
    5. Token vault is consulted to match token with customer account number
    6. Network passes token an PAN to bank
    7. Banks verifies funds and authorizes transaction
    8. Info passes back through network, acquirer and to merchant to complete transaction
* Digital Rights Management(DRM)
  * Suite of tools designed to limit how/where content can be accessed
    * Prevent content from being copied
    * Restrict what devices content can be viewed on
    * May restrict how many times content can be accessed
* Hardware Based Encryption(TPM and HSM)
  * TPM (Trusted Platform Module)
    * is a hardware chip embedded on a computer's motherboard. Used to story cryptographic keys used for encryption.
  * HSM (Hardware Security Module)
    * is similar to TPM, but HSM's are removable or external devices that can added later. Both are used for encryption using RSA keys.
* Geographical Considerations
  * Logins from geographically diverse areas within short period of time
  * Foreign countries
  * Unusual or flagged IP blocks
* Cloud Access Security Broker (CASB)
  * Security Policy Enforcement Points
    * On-premises or in the cloud
    * Placed between the company (consumer) and the cloud provider
    * Ensures policies are enforced when when accessing cloud-based assets
      * Authentication/Single sign-on
      * Credential mapping
      * Device profiling
      * Logging
* Security as a Service (SECaaS)
  * Cloud providers that can offer security service cheaper or more effectively than on-premises:
    * Authentication
    * Anti-virus/malware/spyware
    * Intrusion Detection
    * Pen Testing
    * SIEM
* Differences between CASB and SECaaS
  * SECaaS
    * Cloud providers offer their services, infrastructure, resources, etc. to extend into a company's network
    * They provide the security services typically at a cheaper TCO than the customer organization can
  * CASB
    * Sits between a customer's network and the cloud, acting as a broker or services gateway
    * Enforces the customer organization's policies when accessing anything in the cloud
* Recovery
  * Can users recover their own passwords?
    * Ensure security questions aren't easily discovered via social engineering
      * Favorite dog, children's names, favorite car, vacation spot, sports figure, etc.
  * Policy defines if users need to call help desk or have self-service options
* Secure Protocols and SSL/TLS Inspection
  * Secure Sockets Layer/Transport Layer Security
    * TLS is newer, based on SSL
    * Adds confidentiality and data integrity by encapsulating other protocols
    * Initiates stateful session with handshake
  * On-path type of attack (formerly MiTM)
    * SSL decryptor sits in between the user and server
    * Both parties think they're connecting securely to each other
    * They are connecting to the intermediary SSL decryptor
      * Inspects traffic to block sensitive information leakage, malware, etc.
* Hashing
  * Mathematical algorithm applied to a file before and after transmission
    * If anything within the file changes the hash will be completely different
  * MD5, SHA1, and SHA 2
* API Considerations and API Gateways
  * Security vulnerabilities
    * Authentication
    * SQL injection
    * D/DoS Attacks
  * Portability between formats
  * API Gateways can perform load balancing, virus scanning, orchestration, authentication, data conversion and more
* Recovery Site Options (Cold, Warm, Hot, and Cloud-based Sites)
  * Cold Site
    * Pros:
      * inexpensive
    * Cons:
      * Long recovery time (weeks)
      * All data lost since last backup
      * Funds available to quickly purchase new equipment and/or services
  * Warm Site
    * Pros:
      * Relatively inexpensive, cheaper than hot site
    * Cons:
      * Some equipment (phone, network) but not ready for immediate switch over
      * Recovery time could be days to a week or more
  * Hot Site
    * Pros:
      * Expensive to very expensive (depending on infrastructure, replication, etc.)
    * Cons:
      * Duplicate infrastructure must be acquired and maintained
      * Bandwidth and location constraints may be in place (synchronous failover/replication)
  * Cloud-based
    * Pros:
      * DR-as-a-Service (DRaaS or Cloud DR)
      * Unlimited backup capacity (perceived)
    * Cons:
      * Recovery times may be slower
      * Confusion around types/best practices (on-prem, off-prem, hybrid, multi-cloud, etc. )
* Honeypots and Honey-files
  * Computers or hosts that are set up specifically to become targets of attacks
    * Appear to have sensitive information
    * Monitored to identify hackers or learn their methods and techniques
  * Honey-files 
    * Similar concept but applies to individual files to designed to entice bad actors in and monitor their activities
* Honey-nets
  * Similar to a Honeypot but larger in scale
    * Network setup intentionally for attack so the attackers can be monitored/studied
* Fake Telemetry
  * Applications can pretend to be useful utilities
    * Antivirus and anti-malware fakes
      * Claims to find fake viruses/malware, shows report data, etc.
      * Tricks user into paying for premium support, virus removal
      * Can install additional malware
* DNS Sinkhole
  * DNS server that supplies false results
    * Can be used constructively or maliciously
  * Example use cases
    * Good: 
      * Deploying a DNS sinkhole high up the DNS hierarchy to stop a botnet from operating across the internet
    * Bad: 
      * Malicious actors redirecting users to a malicious website

### Understanding  Virtualization and Cloud Computing
* Cloud Storage
  * Storage external to a company's data center
  * Accessible from outside the network
  * Can be simply storage or there can be automation
  * Access Controls
    * Policies around who can access what data
    * Audit third party providers to ensure their security practices are at least as stringent
    * Is data copied to multiple data centers and where are they located?
* Cloud Computing
  * Virtualization of infrastructure, platform and services
    * Automation and self-service
    * Reduced time to market
    * Increased speed to develop and deliver
* "X" as a service
  * "[insert buzzword] as a Service"
    * Virtualization and commoditization of almost every layer of the IT "stack"
* Infrastructure as a Service (IaaS)
  * IaaS allows for distribution and consumption of resources as a service
    * Multiple users can utilize the same infrastructure (multi-tenant)
    * Allows for elastic scaling as needs and demands increase/decrease
  * Typically priced using a utility model
    * Shifts spend from CAPEX to OPEX
    * Can be private or public (or both)
  * You manage the OS 
    * Applications <- Data <- Runtime <- Middleware <- O/S <-
* IaaS and Automation
  * IaaS also leverages automation and self-service, enabling a customer to select their own hardware/software configurations and provision their own infrastructure
* Platform as a Service (PaaS)
  * A PaaS environment is comprised of computational resources (i.e. test/dev environments) that be easily created and configured
  * No need to order, acquire, rack/stack hardware, configure network, IP addresses, load balancers, VLANS, install software, configure, etc.
  * Test environments can be quickly created,expand as needed, run tests, report and tear down on demand
  * Multi-tenant - where many users can us the same set of resources
  * You manager the Data up
    * Applications <- Data
* Software as a Service (SaaS)
  * Applications that are provided on demand
  * No setup, installation, configuration required
  * You manage nothing
* Types of Clouds
  * Private
    * You manage and maintain all resources
  * Public
    * Cloud provider manages resources
  * Hybrid
    * Public and Private mix/ start internally usually
  * Community
    * Resources are shared among several groups
* Managed Service Providers(MSP)
  * MSP's deliver service either on-prem at customer site, in the MSP's data center, or in third-party data center
    * Network 
    * Application
    * Infrastructure
    * Security
  * MSSP (Managed Security Service Provider) Provide outsourced monitoring and management of security devices and systems (usually 24x7 monitoring)
    * Firewall
    * Intrusion detection
    * VPN's
    * Vulnerability Scans
    * Anti-virus/malware/ransomware
  * On-Prem
    * You own the infrastructure
    * More control on customization and non-standard builds
    * More direct control over policies, management, administration
    * Continual upgrade/refresh of infrastructure
    * Capital expenditure (CAPEX) typically
  * Off-Prem
    * Don't own the equipment
    * Managed by provider
    * Less Control and overall administration
    * No lifecycle or maintenance activities
    * Patching and security managed by provider 
    * Operating expense (OPEX) typically
* Fog Computing
  * Fog computing extends cloud computing to the network edge
    * Edge computing (processing data local to where it was created) is a subset
    * Compromised of compute, network and storage
* Edge Computing
  * Edge and fog computing are sometimes interchanged
    * Edge computing puts resources close to where the data is created
    * Is a subset of fog computing (storage, compute and network close to the edge)
* VDI (Virtual Desktop Infrastructure)
  * Centralized hosting and management of desktop images
  * Users access their desktop from the server
  * VDI Benefits
    * Manage all desktops from a central location
    * Centralized patching and vulnerability mitigation
    * Maintain consistency (non-persistent desktop)
    * Policy can control what group(s) get what image(s)
  * Application Streaming
    * Applications are packaged and streamed to hosts
    * Each application has its own computing environment
  * Terminal Services
    * Applications run on the server and displayed to hosts
    * Users receive graphic updates, mouse/keyboard events, etc.
* Virtualization
  *  Workstations
  *  Servers
  *  Storage
  *  Networking
  *  Taking the capabilities and "personality" of a physical device and converting to a virtual representation
     *  Can perform the same functions as its physical counterpart
     *  Lower infrastructure costs
     *  Increased licensing costs (hypervisor license)
* Containers
  * Type I
    * Host runs on bare metal server and guests run on the host
  * Type II 
    * Host runs on top of OS and guests run inside of host (VMware workstations or Virtual Box)
      * Guest VMs run at a third layer above the hardware
  * Container-Based
    * Operating system Virtualization
      * lightweight
      * Container can start up in milliseconds
      * Shares OS kernel
      * Contains App and Binaries
* Micro-services and API's
  * Treats each function of an application as an independent service that can be altered, updated or taken down without affecting the rest of the application
    * Easily maintained
    * Loosely coupled and extensible
    * Monolithic Architecture (User interface, business logic, data interface<-> Database)
    * Applications are broken apart by functions
      * All services are created individually and deployed separately from one another
    * Each component is loosely coupled
      * Different groups can develop different functions, and each service can be changed/upgraded without affecting the others
    * Deployed via containers
      * Kubernetes and Docker are typically used and each microservice is packed as a container image
    * Quickly Scales
      * Scaling is done based on the changing number of container instances
* Infrastructure as Code (IAC)
  * Methodology to create repeatable processes for deploying infrastructure
    * Replaces static scripts 
    * Collaboration and automation tools like Puppet and Chef enable speed of delivery
    * Reduce shadow IT, makes processes more secure and reduces risk of human error
* Software Defined Networking 
* Software Defined Visibility
* Serverless Architecture
* IaaS, PaaS, FaaS, and SaaS Differentiators
* Service Integrations and Resource Policies
* Transit Gateway
* VM Sprawl Avoidance
* VM Escape

### Implementing Secure Application Development, Deployment, and Automation

### Implementing Cybersecurity Resilience

### Recognizing Security Implications of Embedded and Specialized Systems

### Understanding the Importance of Physical Security Controls

### Understanding the Basics of Cryptographic Concepts




