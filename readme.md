#  Enclosed Microservices Contour with Ticket-Based Authentication

A demonstration project showcasing a **fully enclosed inner microservices contour** with a ticket-based authentication system for microservices. All internal services operate within a private network, with controlled external access through a single, secure API gateway.

##  Key security measures

- **Complete Network Isolation**: Internal services communicate within a private, enclosed network
- **Dual-Layer Authentication**:
  - Ticket-based authentication for external clients (formed with encoding login and password in base64)
  - Service-to-service centralized authentication with ticket-based auth
  - **DNS Segmentation**: Separate internal and external DNS servers for access control
- **Single Entry Point**: All external traffic routes through a secure API Gateway
- **Production-Ready Examples**: Working endpoints demonstrating both public and secured API patterns

##  Architecture Overview

```mermaid
graph TB
    subgraph "External Network / Internet"
        Client[External Client]
        external_dns[External DNS]
    end

    subgraph "Enclosed Microservices Network"
        internal_dns[Internal DNS Server]

        subgraph "Service Layer"
            gate[Gate Service<br/>API Gateway]
            auth[Auth Service<br/>Client Authentication]
            TVM[TVM Service<br/>Service Authentication]
        end

        subgraph "Example Services"
            some_service[Service]
        end
    end

    Client -->|1. DNS Query| external_dns
    ExtDNS -->|2. Resolves to Gate| gate
    Client -->|3. API Request| gate
    Gate -->|4. Validate Client Token| auth
    Auth -->|5. Internal Request with Service Ticket| TVM
    TVM -->|6. Service Auth| auth
    internal_dns -.->|Internal Resolution| gate
    internal_dns -.->|Internal Resolution| auth
    internal_dns -.->|Internal Resolution| TVM
