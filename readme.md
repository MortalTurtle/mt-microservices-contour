#  Enclosed Microservices Contour with mTLS and JWT Token-Based Authentication

A demonstration project showcasing a **fully enclosed inner microservices contour** with a centralized token-based authorization system for microservices and configured mTLS. All internal services operate within a private network.

##  Key security measures

- **Complete Network Isolation**: Internal services communicate within a private, enclosed network
- **Service-to-service centralized authorization**: Using JWT tokens
- **Service-to-service authentication**: Using X509 certificates
- **DNS Segmentation**: Separate internal and external DNS servers for access control

##  Architecture Overview

- **Simplified auth data flow**:
```mermaid
graph TB
    subgraph "Enclosed Microservices Network"
        internal_dns[internal_dns]

        subgraph "Service Layer"
            service1[service1<br/>Public API]
            service2[service2<br/>Client Authentication]
            tokenservice[tokenservice<br/>Service Authentication]
        end
    end

    service2 -->|1. Ping request| service1
    service1 -->|2. Public key request| tokenservice
    tokenservice -->|3. Pub key answer| service1
    service1 -->|4. Pong answer| service2
    internal_dns -.->|Internal Resolution| service1
    internal_dns -.->|Internal Resolution| service2
    internal_dns -.->|Internal Resolution| tokenservice
