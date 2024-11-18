;; Constants and Error Codes
(define-constant ERR-NOT-FOUND u100)
(define-constant ERR-UNAUTHORIZED u101)
(define-constant ERR-DOMAIN-ALREADY-REGISTERED u102)
(define-constant ERR-INVALID-DATA u103)
(define-constant ERR-VERIFICATION-FAILED u104)
(define-constant ERR-NO-PERMISSION u108)
(define-constant ERR-ALREADY-REPORTED u109)
(define-constant ERR-INVALID-USER u110)

;; Data Types
(define-data-var trusted-domain-pattern (string-ascii 253) "")
(define-data-var trusted-verification-pattern (string-ascii 64) "")

;; Data Structures
(define-map domains 
  {domain-name: (string-ascii 253)}
  {owner: principal,
   identity-verified: bool,
   reputation-score: int, 
   registered-at: uint})

(define-map user-roles
  {user: principal}
  {role: (string-ascii 32)})

(define-map domain-reports
  {domain-name: (string-ascii 253),
   reporter: principal}
  {reason-code: int,
   details: (string-utf8 256),
   resolved: bool,
   reported-at: uint})

;; Constants
(define-constant ADMIN-ROLE "admin")
(define-constant MODERATOR-ROLE "moderator")
(define-constant MAX-DOMAIN-LENGTH u253)
(define-constant VERIFICATION-CODE-LENGTH u64)
(define-constant MAX-DETAILS-LENGTH u256)
(define-constant MIN-REASON-CODE 0)
(define-constant MAX-REASON-CODE 100)

;; Input Validation Functions
(define-private (validate-domain-name (input (string-ascii 253)))
  (and 
    (< (len input) MAX-DOMAIN-LENGTH)
    (> (len input) u0)))

(define-private (validate-verification-code (input (string-ascii 64)))
  (and
    (< (len input) VERIFICATION-CODE-LENGTH)
    (> (len input) u0)))

(define-private (validate-report-details (input (string-utf8 256)))
  (and 
    (< (len input) MAX-DETAILS-LENGTH)
    (> (len input) u0)))

(define-private (validate-role (input (string-ascii 32)))
  (or (is-eq input ADMIN-ROLE)
      (is-eq input MODERATOR-ROLE)))

(define-private (validate-reason-code (input int))
  (and (>= input MIN-REASON-CODE)
       (<= input MAX-REASON-CODE)))

(define-private (validate-user (input principal))
  (and
    (not (is-eq input tx-sender))
    (is-some (map-get? user-roles {user: input}))))

;; Input Processing Functions
(define-private (process-domain-input (input (string-ascii 253)))
  (if (validate-domain-name input)
      (ok input)
      (err ERR-INVALID-DATA)))

(define-private (process-verification-input (input (string-ascii 64)))
  (if (validate-verification-code input)
      (ok input) 
      (err ERR-INVALID-DATA)))

(define-private (process-details-input (input (string-utf8 256)))
  (if (validate-report-details input)
      (ok input)
      (err ERR-INVALID-DATA)))

(define-private (process-role-input (input (string-ascii 32)))
  (if (validate-role input)
      (ok input)
      (err ERR-INVALID-DATA)))

(define-private (process-reason-code-input (input int))
  (if (validate-reason-code input)
      (ok input)
      (err ERR-INVALID-DATA)))

(define-private (process-user-input (input principal))
  (if (validate-user input)
      (ok input)
      (err ERR-INVALID-USER)))

;; Update all function calls to handle Response types:
(define-private (verify-domain-ownership
                 (domain-name (string-ascii 253))
                 (verification-code (string-ascii 64))
                 (owner principal))
  (let ((domain-result (process-domain-input domain-name))
        (code-result (process-verification-input verification-code)))
    (match domain-result 
      result-ok
      (match code-result
        code-ok 
        (let ((domain-buff (unwrap! (to-consensus-buff? result-ok) false))
              (code-buff (unwrap! (to-consensus-buff? code-ok) false)))
          (is-eq (sha256 code-buff)
                 (sha256 domain-buff)))
        err false)
      err false)))

;; Domain Registration
(define-public (register-domain
                (domain-name (string-ascii 253))
                (verification-code (string-ascii 64)))
  (let ((domain-result (process-domain-input domain-name))
        (code-result (process-verification-input verification-code)))
    (match domain-result
      domain-ok
      (match code-result
        code-ok
        (let ((existing-domain (map-get? domains {domain-name: domain-ok})))
          (asserts! (is-none existing-domain) (err ERR-DOMAIN-ALREADY-REGISTERED))
          (asserts! (verify-domain-ownership domain-ok code-ok tx-sender) 
                   (err ERR-VERIFICATION-FAILED))
          (map-set domains 
                  {domain-name: domain-ok}
                  {owner: tx-sender,
                   identity-verified: false,
                   reputation-score: 0,
                   registered-at: block-height})
          (ok true))
        err (err ERR-INVALID-DATA))
      err (err ERR-INVALID-DATA))))

;; Domain Information Lookup
(define-read-only (get-domain-info (domain-name (string-ascii 253)))
  (match (process-domain-input domain-name)
    domain-ok 
    (match (map-get? domains {domain-name: domain-ok})
      domain-data (ok domain-data)
      (err ERR-NOT-FOUND))
    err (err ERR-INVALID-DATA)))

;; Report Suspicious Domain
(define-public (report-domain
                (domain-name (string-ascii 253))
                (reason-code int)
                (details (string-utf8 256)))
  (match (process-domain-input domain-name)
    domain-ok
    (match (process-reason-code-input reason-code)
      reason-ok
      (match (process-details-input details)
        details-ok
        (let ((domain-data (map-get? domains {domain-name: domain-ok})))
          (asserts! (is-some domain-data) (err ERR-NOT-FOUND))
          (let ((existing-report (map-get? domain-reports 
                                         {domain-name: domain-ok, 
                                          reporter: tx-sender})))
            (asserts! (is-none existing-report) (err ERR-ALREADY-REPORTED))
            (map-set domain-reports 
                    {domain-name: domain-ok, 
                     reporter: tx-sender}
                    {reason-code: reason-ok,
                     details: details-ok,
                     resolved: false,
                     reported-at: block-height})
            (ok true)))
        err (err ERR-INVALID-DATA))
      err (err ERR-INVALID-DATA))
    err (err ERR-INVALID-DATA)))

;; Get Report Status
(define-read-only (get-report-status
                   (domain-name (string-ascii 253))
                   (reporter principal))
  (match (process-domain-input domain-name)
    domain-ok
    (match (map-get? domain-reports 
                    {domain-name: domain-ok,
                     reporter: reporter})
      report-data (ok (get resolved report-data))
      (err ERR-NOT-FOUND))
    err (err ERR-INVALID-DATA)))

;; Admin Role Management
(define-public (assign-role
                (user principal)
                (role (string-ascii 32)))
  (match (process-user-input user)
    user-ok
    (match (process-role-input role)
      role-ok
      (begin
        (asserts! (has-admin-role? tx-sender) (err ERR-NO-PERMISSION))
        (map-set user-roles 
                {user: user-ok} 
                {role: role-ok})
        (ok true))
      err (err ERR-INVALID-DATA))
    err (err ERR-INVALID-USER)))

(define-private (has-admin-role? (user principal))
  (match (map-get? user-roles {user: user})
    role-data (is-eq (get role role-data) ADMIN-ROLE)
    false))

;; Role Information
(define-read-only (get-user-role (user principal))
  (match (map-get? user-roles {user: user})
    role-data (ok (get role role-data))
    (err ERR-NOT-FOUND)))