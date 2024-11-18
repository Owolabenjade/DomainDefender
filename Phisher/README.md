# Secure Domain Registry Smart Contract

A Clarity smart contract for registering and managing web3 domain names with built-in security features, verification, and reputation tracking.

### Key Features

- Domain registration with ownership verification
- Identity verification system
- Reputation scoring mechanism
- Suspicious domain reporting
- Role-based access control (Admin/Moderator)
- Input validation and security checks

## Technical Architecture

### Data Structures

```clarity
domains: Map
- Domain name (string-ascii 253)
- Owner (principal)
- Identity verification status
- Reputation score
- Registration timestamp

user-roles: Map
- User (principal)
- Role (admin/moderator)

domain-reports: Map
- Domain name & reporter
- Reason code
- Report details
- Resolution status
- Report timestamp
```

### Core Functions

1. Domain Management
```clarity
register-domain
get-domain-info
verify-domain-ownership
```

2. Reporting System
```clarity
report-domain
get-report-status
```

3. Administration
```clarity
assign-role
get-user-role
```

## Security Features

- Cryptographic ownership verification
- Input validation for all parameters
- Role-based access control
- Anti-spam measures for domain reporting
- Response type handling for all operations

## Setup Instructions

1. Deploy contract:
```bash
clarinet contract deploy domain-registry
```

2. Initialize admin role:
```clarity
(contract-call? .domain-registry assign-role 
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 
  "admin")
```

## Usage Example

1. Register a domain:
```clarity
(contract-call? .domain-registry register-domain
  "my-domain.btc"
  "verification-code")
```

2. Report suspicious activity:
```clarity
(contract-call? .domain-registry report-domain
  "suspicious-domain.btc"
  1
  "Suspicious activity details")
```

## Error Codes

- `ERR-NOT-FOUND (u100)`: Resource not found
- `ERR-UNAUTHORIZED (u101)`: Unauthorized access
- `ERR-DOMAIN-ALREADY-REGISTERED (u102)`: Domain exists
- `ERR-INVALID-DATA (u103)`: Invalid input
- `ERR-VERIFICATION-FAILED (u104)`: Verification failed
- `ERR-NO-PERMISSION (u108)`: Insufficient permissions
- `ERR-ALREADY-REPORTED (u109)`: Duplicate report
- `ERR-INVALID-USER (u110)`: Invalid user

## Testing

Run test suite:
```bash
clarinet test domain-registry_test.clar
```

## Contributing

1. Fork repository
2. Create feature branch
3. Submit pull request with tests