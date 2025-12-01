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
        client[External Client]
        external_dns[external_dns]
    end

    subgraph "Enclosed Microservices Network"
        internal_dns[internal_dns]

        subgraph "Service Layer"
            gate[gate<br/>Public API]
            auth[auth<br/>Client Authentication]
            TVM[tvm<br/>Service Authentication]
        end
    end

    client -->|1. Public API Request| gate
    gate -->|2. Client authentication request| auth
    auth -->|3. Ticket request| TVM
    TVM -->|4. Gate ticket| auth
    auth -->|5. Client authentication answer| gate
    gate -->|6. Public API Answer| client
    internal_dns -.->|Internal Resolution| gate
    internal_dns -.->|Internal Resolution| auth
    internal_dns -.->|Internal Resolution| TVM
    external_dns -.->|External Resolution| gate
